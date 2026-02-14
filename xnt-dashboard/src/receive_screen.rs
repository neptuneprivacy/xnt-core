use std::cmp::max;
use std::sync::Arc;
use std::sync::Mutex;

use crossterm::event::Event;
use crossterm::event::KeyCode;
use crossterm::event::KeyEventKind;
use neptune_privacy::application::config::network::Network;
use neptune_privacy::application::rpc::auth;
use neptune_privacy::state::wallet::address::KeyType;
use neptune_privacy::state::wallet::address::ReceivingAddress;
use ratatui::layout::Alignment;
use ratatui::layout::Margin;
use ratatui::style::Color;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::text::Text;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Widget;
use tarpc::context;

use super::dashboard_app::ConsoleIO;
use super::dashboard_app::DashboardEvent;
use super::overview_screen::VerticalRectifier;
use super::screen::Screen;
use crate::dashboard_rpc_client::DashboardRpcClient;

#[derive(Debug, Clone)]
pub struct ReceiveScreen {
    active: bool,
    fg: Color,
    bg: Color,
    in_focus: bool,
    /// Which key type to use when generating / showing a receiving address.
    current_key_type: KeyType,
    data: Arc<std::sync::Mutex<Option<ReceivingAddress>>>,
    server: Arc<DashboardRpcClient>,
    generating: Arc<Mutex<bool>>,
    escalatable_event: Arc<std::sync::Mutex<Option<DashboardEvent>>>,
    network: Network,
    token: auth::Token,
}

impl ReceiveScreen {
    pub fn new(rpc_server: Arc<DashboardRpcClient>, network: Network, token: auth::Token) -> Self {
        let data = Arc::new(Mutex::new(None));
        let server = rpc_server.clone();
        let escalatable_event = Arc::new(std::sync::Mutex::new(None));
        let s = Self {
            active: false,
            fg: Color::Gray,
            bg: Color::Black,
            in_focus: false,
            current_key_type: KeyType::Generation,
            data: data.clone(),
            server: rpc_server,
            generating: Arc::new(Mutex::new(false)),
            escalatable_event: escalatable_event.clone(),
            network,
            token,
        };
        // Preload address so it's ready when user opens Receive (no need to press Enter first).
        s.populate_receiving_address_async(server, token, data, s.current_key_type);
        s
    }

    fn populate_receiving_address_async(
        &self,
        rpc_client: Arc<DashboardRpcClient>,
        token: auth::Token,
        data: Arc<Mutex<Option<ReceivingAddress>>>,
        key_type: KeyType,
    ) {
        if data.lock().unwrap().is_none() {
            let escalatable_event = self.escalatable_event.clone();

            tokio::spawn(async move {
                // Try to get the latest address; if none exists yet (or any error),
                // fall back to creating the next receiving address.
                let receiving_address = match rpc_client
                    .latest_address(context::current(), token, key_type)
                    .await
                    .ok()
                    .and_then(|rpc_result| rpc_result.ok())
                {
                    Some(addr) => addr,
                    None => match rpc_client
                        .next_receiving_address(context::current(), token, key_type)
                        .await
                        .ok()
                        .and_then(|rpc_result| rpc_result.ok())
                    {
                        Some(addr) => addr,
                        None => {
                            // Give up silently; UI will just show "-" for address.
                            return;
                        }
                    },
                };
                *data.lock().unwrap() = Some(receiving_address);
                *escalatable_event.lock().unwrap() = Some(DashboardEvent::RefreshScreen);
            });
        }
    }

    fn generate_new_receiving_address_async(
        &self,
        rpc_client: Arc<DashboardRpcClient>,
        token: auth::Token,
        data: Arc<Mutex<Option<ReceivingAddress>>>,
        generating: Arc<Mutex<bool>>,
        key_type: KeyType,
    ) {
        let escalatable_event = self.escalatable_event.clone();
        tokio::spawn(async move {
            *generating.lock().unwrap() = true;
            let receiving_address = rpc_client
                .next_receiving_address(context::current(), token, key_type)
                .await
                .unwrap()
                .unwrap();
            *data.lock().unwrap() = Some(receiving_address);
            *generating.lock().unwrap() = false;
            *escalatable_event.lock().unwrap() = Some(DashboardEvent::RefreshScreen);
        });
    }

    pub fn handle(&mut self, event: DashboardEvent) -> Option<DashboardEvent> {
        let mut escalate_event = None;
        if self.in_focus {
            if let DashboardEvent::ConsoleEvent(Event::Key(key)) = event {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Enter => {
                            self.generate_new_receiving_address_async(
                                self.server.clone(),
                                self.token,
                                self.data.clone(),
                                self.generating.clone(),
                                self.current_key_type,
                            );
                            escalate_event = Some(DashboardEvent::RefreshScreen);
                        }
                        // Toggle between Generation and dCTIDH receiving address types.
                        KeyCode::Char('t') | KeyCode::Char('T') => {
                            self.current_key_type = match self.current_key_type {
                                KeyType::Generation | KeyType::GenerationSubAddr => KeyType::dCTIDH,
                                KeyType::dCTIDH | KeyType::dCTIDHSubAddr => KeyType::Generation,
                                KeyType::Symmetric => KeyType::Generation,
                            };
                            // Clear cached address so we fetch a fresh one for the new key type.
                            *self.data.lock().unwrap() = None;
                            self.populate_receiving_address_async(
                                self.server.clone(),
                                self.token,
                                self.data.clone(),
                                self.current_key_type,
                            );
                            escalate_event = Some(DashboardEvent::RefreshScreen);
                        }
                        KeyCode::Char('c') => {
                            if let Some(address) = self.data.lock().unwrap().as_ref() {
                                let encoded = address.to_bech32m(self.network).unwrap();
                                return Some(DashboardEvent::ConsoleMode(
                                    ConsoleIO::InputRequested(format!("{encoded}\n\n")),
                                ));
                            }
                        }
                        _ => {
                            escalate_event = Some(event);
                        }
                    }
                }
            }
        }
        escalate_event
    }
}

impl Screen for ReceiveScreen {
    fn activate(&mut self) {
        self.active = true;
        let server_arc = self.server.clone();
        let data_arc = self.data.clone();
        let token = self.token;
        self.populate_receiving_address_async(server_arc, token, data_arc, self.current_key_type);
    }

    fn deactivate(&mut self) {
        self.active = false;
    }

    fn focus(&mut self) {
        self.fg = Color::White;
        self.in_focus = true;
    }

    fn unfocus(&mut self) {
        self.fg = Color::Gray;
        self.in_focus = false;
    }

    fn escalatable_event(&self) -> Arc<std::sync::Mutex<Option<DashboardEvent>>> {
        self.escalatable_event.clone()
    }
}

impl Widget for ReceiveScreen {
    fn render(self, area: ratatui::layout::Rect, buf: &mut ratatui::buffer::Buffer) {
        // receive box
        let style: Style = if self.in_focus {
            Style::default().fg(Color::Rgb(49, 64, 167)).bg(self.bg)
        } else {
            Style::default().fg(Color::Gray).bg(self.bg)
        };
        Block::default()
            .borders(Borders::ALL)
            .title("Receive")
            .style(style)
            .render(area, buf);

        // divide the overview box vertically into subboxes,
        // and render each separately
        let style = Style::default().bg(self.bg).fg(self.fg);
        let inner = area.inner(Margin {
            vertical: 1,
            horizontal: 1,
        });
        let mut vrecter = VerticalRectifier::new(inner);

        // display address
        let receiving_address = self.data.lock().unwrap().to_owned();
        let key_type_label = match self.current_key_type {
            KeyType::Generation | KeyType::GenerationSubAddr => "Generation",
            KeyType::Symmetric => "Symmetric",
            KeyType::dCTIDH | KeyType::dCTIDHSubAddr => "CTIDH",
        };
        let (mut address, address_abbrev) = match receiving_address {
            Some(addr) => match self.current_key_type {
                KeyType::dCTIDH => {
                    let bech = addr.to_bech32m(self.network).unwrap();
                    (bech.clone(), bech)
                }
                _ => (
                    addr.to_bech32m(self.network).unwrap(),
                    addr.to_bech32m_abbreviated(self.network).unwrap(),
                ),
            },
            None => ("-".to_string(), "-".to_string()),
        };
        let width = max(0, inner.width as isize - 2) as usize;
        if width > 0 {
            let mut address_lines = vec![];

            // display generation instructions at the top so they are always visible,
            // even when the address box is very tall.
            if *self.generating.lock().unwrap() {
                let generating_text =
                    Paragraph::new(Span::from("Generating ...")).alignment(Alignment::Left);
                generating_text.render(vrecter.next(1), buf);
            } else {
                let action = if self.in_focus {
                    "generate a new address"
                } else {
                    "focus"
                };
                let instructions = Line::from(vec![
                    Span::from("Press "),
                    Span::styled("Enter ↵", Style::default().fg(Color::Rgb(49, 64, 167))),
                    Span::from(" to "),
                    Span::from(action),
                    Span::from(" ("),
                    Span::styled(
                        key_type_label,
                        Style::default().fg(Color::Rgb(49, 64, 167)),
                    ),
                    Span::from(").  Press "),
                    Span::styled(
                        "T",
                        Style::default().fg(Color::Rgb(49, 64, 167)),
                    ),
                    Span::from(" to toggle Generation/CTIDH."),
                ]);
                let style = Style::default().fg(self.fg);
                let generate_instructions = Paragraph::new(instructions).style(style);
                generate_instructions.render(vrecter.next(1), buf);
            }

            // display copy instructions just under the main instructions
            if self.in_focus {
                let style = Style::default().fg(self.fg);
                let instructions = Line::from(vec![
                    Span::from("Press "),
                    Span::styled(
                        "C",
                        if self.in_focus {
                            Style::default().fg(Color::Rgb(49, 64, 167))
                        } else {
                            style
                        },
                    ),
                    Span::from(" to show current address in console mode."),
                ]);
                let generate_instructions = Paragraph::new(instructions).style(style);
                generate_instructions.render(vrecter.next(1), buf);
            }

            // then show abbreviated and full address below the instructions
            let address_abbrev_rect = vrecter.next(1 + 2);
            let address_abbrev_display = Paragraph::new(Text::from(address_abbrev))
                .style(style)
                .block(Block::default().borders(Borders::ALL).title(Span::styled(
                    format!("Receiving Address ({key_type_label}, abbreviated)"),
                    Style::default(),
                )))
                .alignment(Alignment::Left);
            address_abbrev_display.render(address_abbrev_rect, buf);

            vrecter.next(1);

            while address.len() > width {
                let split_at = address
                    .char_indices()
                    .take_while(|(i, c)| i + c.len_utf8() <= width)
                    .last()
                    .map(|(i, c)| i + c.len_utf8())
                    .unwrap_or_else(|| {
                        address.chars().next().map(|c| c.len_utf8()).unwrap_or(0)
                    });
                let (line, remainder) = address.split_at(split_at);
                address_lines.push(line.to_owned());

                address = remainder.to_owned();
            }
            address_lines.push(address);

            let address_rect = vrecter.next((address_lines.len() + 2).try_into().unwrap());
            if address_rect.height > 0 {
                let address_display = Paragraph::new(Text::from(address_lines.join("\n")))
                    .style(style)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(Span::styled(
                                format!("Receiving Address ({key_type_label})"),
                                Style::default(),
                            )),
                    )
                    .alignment(Alignment::Left);
                address_display.render(address_rect, buf);
            }
        }
    }
}
