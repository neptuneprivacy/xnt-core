use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use crossterm::event::Event;
use crossterm::event::KeyCode;
use crossterm::event::KeyEventKind;
use neptune_privacy::application::config::network::Network;
use neptune_privacy::application::rpc::auth;
use neptune_privacy::protocol::consensus::bridge::deposit_announcement::parse_leviathan_address;
use neptune_privacy::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use num_traits::Zero;
use ratatui::layout::Margin;
use ratatui::style::Color;
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::text::Text;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Widget;
use ratatui::widgets::Wrap;
use tarpc::context;
use tokio::sync::Mutex;

use super::dashboard_app::ConsoleIO;
use super::dashboard_app::DashboardEvent;
use super::overview_screen::VerticalRectifier;
use super::screen::Screen;
use crate::dashboard_rpc_client::DashboardRpcClient;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BridgeWidget {
    LeviathanAccount,
    Amount,
    Fee,
    Ok,
    Notice,
}

#[derive(Default, Debug, Clone)]
enum ResetType {
    #[default]
    None,
    #[allow(dead_code)]
    Form,
    Notice,
}

#[derive(Debug, Clone)]
pub struct BridgeScreen {
    active: bool,
    fg: Color,
    bg: Color,
    in_focus: bool,
    leviathan_account: String,
    amount: String,
    fee: String,
    rpc_client: Arc<DashboardRpcClient>,
    focus: Arc<Mutex<BridgeWidget>>,
    notice: Arc<Mutex<String>>,
    reset_me: Arc<Mutex<ResetType>>,
    escalatable_event: Arc<std::sync::Mutex<Option<DashboardEvent>>>,
    network: Network,
    token: auth::Token,
}

impl BridgeScreen {
    pub fn new(rpc_server: Arc<DashboardRpcClient>, network: Network, token: auth::Token) -> Self {
        BridgeScreen {
            active: false,
            fg: Color::Gray,
            bg: Color::Black,
            in_focus: false,
            leviathan_account: String::new(),
            amount: String::new(),
            fee: "".to_string(),
            rpc_client: rpc_server,
            focus: Arc::new(Mutex::new(BridgeWidget::LeviathanAccount)),
            notice: Arc::new(Mutex::new(String::new())),
            reset_me: Arc::new(Mutex::new(Default::default())),
            escalatable_event: Arc::new(std::sync::Mutex::new(None)),
            network,
            token,
        }
    }

    async fn bridge_deposit_sequence(
        rpc_client: Arc<DashboardRpcClient>,
        token: auth::Token,
        leviathan_account: String,
        amount: String,
        fee: String,
        notice_arc: Arc<Mutex<String>>,
        reset_me: Arc<Mutex<ResetType>>,
        network: Network,
        refresh_tx: tokio::sync::mpsc::Sender<()>,
    ) {
        const BRIDGE_DEADLINE_IN_SECONDS: u64 = 60;

        *notice_arc.lock().await = "Validating inputs...".to_string();
        let _ = refresh_tx.send(()).await;

        let leviathan_account_id = match parse_leviathan_address(&leviathan_account, network) {
            Ok(id) => id,
            Err(e) => {
                *notice_arc.lock().await = format!("Invalid Leviathan address or account id: {e}");
                *reset_me.lock().await = ResetType::Notice;
                let _ = refresh_tx.send(()).await;
                return;
            }
        };

        // Validate amount
        let valid_amount = match NativeCurrencyAmount::coins_from_str(&amount) {
            Ok(a) if !a.is_negative() && !a.is_zero() => a,
            Ok(_) => {
                *notice_arc.lock().await = "Amount must be positive".to_string();
                *reset_me.lock().await = ResetType::Notice;
                let _ = refresh_tx.send(()).await;
                return;
            }
            Err(e) => {
                *notice_arc.lock().await = format!("Invalid amount: {e}");
                *reset_me.lock().await = ResetType::Notice;
                let _ = refresh_tx.send(()).await;
                return;
            }
        };

        // Validate fee
        let valid_fee = match NativeCurrencyAmount::coins_from_str(&fee) {
            Ok(a) if !a.is_negative() => a,
            Ok(a) => {
                *notice_arc.lock().await = format!("Invalid fee: {a}");
                *reset_me.lock().await = ResetType::Notice;
                let _ = refresh_tx.send(()).await;
                return;
            }
            Err(e) => {
                *notice_arc.lock().await = format!("Invalid fee: {e}");
                *reset_me.lock().await = ResetType::Notice;
                let _ = refresh_tx.send(()).await;
                return;
            }
        };

        *notice_arc.lock().await = "Submitting bridge deposit...".to_string();
        let _ = refresh_tx.send(()).await;

        let mut ctx = context::current();
        ctx.deadline = SystemTime::now() + Duration::from_secs(BRIDGE_DEADLINE_IN_SECONDS);

        let result = rpc_client
            .bridge_deposit(
                ctx,
                token,
                leviathan_account_id,
                valid_amount,
                valid_fee,
                0,    // exclude_recent_blocks
                None, // max_inputs
            )
            .await;

        match result {
            Ok(Ok(_)) => {
                *notice_arc.lock().await =
                    "Bridge deposit broadcast! Relayer will mint WXNT on Leviathan.".to_string();
                *reset_me.lock().await = ResetType::Form;
            }
            Ok(Err(e)) => {
                *notice_arc.lock().await = format!("Bridge deposit error: {e}");
                *reset_me.lock().await = ResetType::Notice;
            }
            Err(e) => {
                *notice_arc.lock().await = format!("RPC error: {e}");
                *reset_me.lock().await = ResetType::Notice;
            }
        }
        let _ = refresh_tx.send(()).await;
    }

    pub fn handle(
        &mut self,
        event: DashboardEvent,
        refresh_tx: tokio::sync::mpsc::Sender<()>,
    ) -> Option<DashboardEvent> {
        let mut escalate_event = None;

        // Handle reset
        if let Ok(mut reset_me_guard) = self.reset_me.try_lock() {
            match *reset_me_guard {
                ResetType::Form => {
                    self.leviathan_account = String::new();
                    self.amount = String::new();
                    self.fee = String::new();
                    if let Ok(mut n) = self.notice.try_lock() {
                        *n = String::new();
                    }
                }
                ResetType::Notice => {
                    // Don't clear notice — keep it visible
                }
                ResetType::None => {}
            }
            *reset_me_guard = ResetType::None;
        }

        if self.in_focus {
            match event {
                DashboardEvent::ConsoleEvent(Event::Key(key))
                    if key.kind == KeyEventKind::Press =>
                {
                    match key.code {
                        KeyCode::Enter => {
                            if let Ok(mut own_focus) = self.focus.try_lock() {
                                match *own_focus {
                                    BridgeWidget::LeviathanAccount => {
                                        return Some(DashboardEvent::ConsoleMode(
                                            ConsoleIO::InputRequested(
                                                "Enter Leviathan address (mtst1...) or account ID (hex):\n".to_string(),
                                            ),
                                        ));
                                    }
                                    BridgeWidget::Amount => {
                                        *own_focus = BridgeWidget::Fee;
                                        escalate_event = Some(DashboardEvent::RefreshScreen);
                                    }
                                    BridgeWidget::Fee => {
                                        *own_focus = BridgeWidget::Ok;
                                        escalate_event = Some(DashboardEvent::RefreshScreen);
                                    }
                                    BridgeWidget::Ok => {
                                        let rpc_client = self.rpc_client.clone();
                                        let leviathan_account = self.leviathan_account.clone();
                                        let amount = self.amount.clone();
                                        let fee = self.fee.clone();
                                        let notice = self.notice.clone();
                                        let reset_me = self.reset_me.clone();
                                        let network = self.network;
                                        let token = self.token;

                                        tokio::spawn(Self::bridge_deposit_sequence(
                                            rpc_client,
                                            token,
                                            leviathan_account,
                                            amount,
                                            fee,
                                            notice,
                                            reset_me,
                                            network,
                                            refresh_tx,
                                        ));
                                    }
                                    BridgeWidget::Notice => {}
                                }
                            }
                        }
                        KeyCode::Up => {
                            if let Ok(mut own_focus) = self.focus.try_lock() {
                                *own_focus = match *own_focus {
                                    BridgeWidget::LeviathanAccount => BridgeWidget::Ok,
                                    BridgeWidget::Amount => BridgeWidget::LeviathanAccount,
                                    BridgeWidget::Fee => BridgeWidget::Amount,
                                    BridgeWidget::Ok => BridgeWidget::Fee,
                                    BridgeWidget::Notice => BridgeWidget::Notice,
                                };
                                escalate_event = Some(DashboardEvent::RefreshScreen);
                            } else {
                                escalate_event = Some(event);
                            }
                        }
                        KeyCode::Down => {
                            if let Ok(mut own_focus) = self.focus.try_lock() {
                                *own_focus = match *own_focus {
                                    BridgeWidget::LeviathanAccount => BridgeWidget::Amount,
                                    BridgeWidget::Amount => BridgeWidget::Fee,
                                    BridgeWidget::Fee => BridgeWidget::Ok,
                                    BridgeWidget::Ok => BridgeWidget::LeviathanAccount,
                                    BridgeWidget::Notice => BridgeWidget::Notice,
                                };
                                escalate_event = Some(DashboardEvent::RefreshScreen);
                            } else {
                                escalate_event = Some(event);
                            }
                        }
                        KeyCode::Char(c) => {
                            if let Ok(own_focus) = self.focus.try_lock() {
                                match *own_focus {
                                    BridgeWidget::Amount => {
                                        self.amount.push(c);
                                        escalate_event = Some(DashboardEvent::RefreshScreen);
                                    }
                                    BridgeWidget::Fee => {
                                        self.fee.push(c);
                                        escalate_event = Some(DashboardEvent::RefreshScreen);
                                    }
                                    _ => {
                                        escalate_event = Some(event);
                                    }
                                }
                            } else {
                                escalate_event = Some(event);
                            }
                        }
                        KeyCode::Backspace => {
                            if let Ok(own_focus) = self.focus.try_lock() {
                                match *own_focus {
                                    BridgeWidget::Amount => {
                                        self.amount.pop();
                                        escalate_event = Some(DashboardEvent::RefreshScreen);
                                    }
                                    BridgeWidget::Fee => {
                                        self.fee.pop();
                                        escalate_event = Some(DashboardEvent::RefreshScreen);
                                    }
                                    _ => {
                                        escalate_event = Some(event);
                                    }
                                }
                            } else {
                                escalate_event = Some(event);
                            }
                        }
                        _ => {
                            escalate_event = Some(event);
                        }
                    }
                }
                DashboardEvent::ConsoleMode(ConsoleIO::InputSupplied(string)) => {
                    if let Ok(mut own_focus) = self.focus.try_lock() {
                        let trimmed = string.trim().to_string();
                        match *own_focus {
                            BridgeWidget::LeviathanAccount => {
                                self.leviathan_account = trimmed;
                                *own_focus = BridgeWidget::Amount;
                            }
                            _ => {
                                // Default: treat as leviathan account
                                self.leviathan_account = trimmed;
                                *own_focus = BridgeWidget::Amount;
                            }
                        }
                        escalate_event = Some(DashboardEvent::RefreshScreen);
                    } else {
                        escalate_event = Some(DashboardEvent::ConsoleMode(
                            ConsoleIO::InputSupplied(string),
                        ));
                    }
                }
                _ => {
                    escalate_event = None;
                }
            }
        }
        escalate_event
    }
}

impl Screen for BridgeScreen {
    fn activate(&mut self) {
        self.active = true;
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

impl Widget for BridgeScreen {
    fn render(self, area: ratatui::layout::Rect, buf: &mut ratatui::buffer::Buffer) {
        let own_focus = if let Ok(of) = self.focus.try_lock() {
            *of
        } else {
            BridgeWidget::Notice
        };

        let style: Style = if self.in_focus {
            Style::default().fg(Color::Rgb(49, 64, 167)).bg(self.bg)
        } else {
            Style::default().fg(Color::Gray).bg(self.bg)
        };
        Block::default()
            .borders(Borders::ALL)
            .title("Bridge Deposit (XNT \u{2192} Leviathan)")
            .style(style)
            .render(area, buf);

        let style = Style::default().bg(self.bg).fg(self.fg);
        let focus_style = Style::default().bg(self.bg).fg(Color::Rgb(49, 64, 167));
        let inner = area.inner(Margin {
            vertical: 1,
            horizontal: 1,
        });

        if inner.width < 3 {
            return;
        }
        let width = (inner.width - 2) as usize;
        let mut vrecter = VerticalRectifier::new(inner);

        // Info line
        let info_rect = vrecter.next(2);
        let info = Paragraph::new(Text::from(vec![
            Line::from(Span::styled(
                "Lock XNT on L1 to receive WXNT on Leviathan (L2)",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                "Use arrow keys to navigate, Enter to input, Esc to go back",
                Style::default().fg(Color::DarkGray),
            )),
        ]));
        info.render(info_rect, buf);

        // Leviathan Account field (console input)
        let leviathan_account = &self.leviathan_account;
        let mut acct_lines = vec![];
        let mut acct_str = leviathan_account.clone();
        while acct_str.len() > width {
            let split_at = acct_str
                .char_indices()
                .take_while(|(i, c)| i + c.len_utf8() <= width)
                .last()
                .map(|(i, c)| i + c.len_utf8())
                .unwrap_or_else(|| acct_str.chars().next().map(|c| c.len_utf8()).unwrap_or(0));
            let (line, remainder) = acct_str.split_at(split_at);
            acct_lines.push(line.to_owned());
            acct_str = remainder.to_owned();
        }
        acct_lines.push(acct_str);

        let acct_rect = vrecter.next((acct_lines.len() + 2).try_into().unwrap_or(3));
        if acct_rect.height > 0 {
            let acct_widget = Paragraph::new(Text::from(acct_lines.join("\n")))
                .style(
                    if own_focus == BridgeWidget::LeviathanAccount && self.in_focus {
                        focus_style
                    } else {
                        style
                    },
                )
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Leviathan Address or Account ID"),
                );
            acct_widget.render(acct_rect, buf);
        }

        // Console hint for Leviathan Account
        let hint_rect = vrecter.next(1);
        if hint_rect.height > 0 && self.in_focus && own_focus == BridgeWidget::LeviathanAccount {
            let hint = Paragraph::new(Line::from(vec![
                Span::from("Press "),
                Span::styled("Enter", Style::default().fg(Color::Rgb(49, 64, 167))),
                Span::from(" to enter Leviathan account via console."),
            ]))
            .style(style);
            hint.render(hint_rect, buf);
        }

        // Amount field
        let amount_rect = vrecter.next(3);
        let amount_widget = Paragraph::new(Line::from(vec![
            Span::from(self.amount.as_str()),
            if own_focus == BridgeWidget::Amount {
                Span::styled(
                    "|",
                    if self.in_focus {
                        Style::default().add_modifier(Modifier::RAPID_BLINK)
                    } else {
                        style
                    },
                )
            } else {
                Span::from(" ")
            },
        ]))
        .style(if own_focus == BridgeWidget::Amount && self.in_focus {
            focus_style
        } else {
            style
        })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Amount (XNT)")
                .style(if own_focus == BridgeWidget::Amount && self.in_focus {
                    focus_style
                } else {
                    style
                }),
        );
        amount_widget.render(amount_rect, buf);

        // Fee field
        let fee_rect = vrecter.next(3);
        let fee_widget = Paragraph::new(Line::from(vec![
            Span::from(self.fee.as_str()),
            if own_focus == BridgeWidget::Fee {
                Span::styled(
                    "|",
                    if self.in_focus {
                        Style::default().add_modifier(Modifier::RAPID_BLINK)
                    } else {
                        style
                    },
                )
            } else {
                Span::from(" ")
            },
        ]))
        .style(if own_focus == BridgeWidget::Fee && self.in_focus {
            focus_style
        } else {
            style
        })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Fee (XNT)")
                .style(if own_focus == BridgeWidget::Fee && self.in_focus {
                    focus_style
                } else {
                    style
                }),
        );
        fee_widget.render(fee_rect, buf);

        // Deposit button
        let mut button_rect = vrecter.next(3);
        button_rect.width = 12;
        let button_widget = Paragraph::new(Span::styled(
            " DEPOSIT ",
            if own_focus == BridgeWidget::Ok && self.in_focus {
                focus_style
            } else {
                style
            },
        ))
        .block(Block::default().borders(Borders::ALL).style(
            if own_focus == BridgeWidget::Ok && self.in_focus {
                focus_style
            } else {
                style
            },
        ));
        button_widget.render(button_rect, buf);

        // Notice area
        if let Ok(notice_text) = self.notice.try_lock() {
            if !notice_text.is_empty() {
                vrecter.next(1);
                let notice_rect = vrecter.next(10);
                let notice_widget = Paragraph::new(notice_text.as_str()).wrap(Wrap { trim: true });
                notice_widget.render(notice_rect, buf);
            }
        }
    }
}
