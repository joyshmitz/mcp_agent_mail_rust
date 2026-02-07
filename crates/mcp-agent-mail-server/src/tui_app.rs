//! Top-level TUI application model for `AgentMailTUI`.
//!
//! [`MailAppModel`] implements the `ftui_runtime` [`Model`] trait,
//! orchestrating screen switching, global keybindings, tick dispatch,
//! and shared-state access.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use ftui::Frame;
use ftui::layout::Rect;
use ftui::widgets::Widget;
use ftui::widgets::command_palette::{ActionItem, CommandPalette, PaletteAction};
use ftui::{Event, KeyCode, KeyEventKind, Modifiers};
use ftui_runtime::program::{Cmd, Model};

use crate::tui_bridge::TuiSharedState;
use crate::tui_events::MailEvent;
use crate::tui_screens::{
    ALL_SCREEN_IDS, MAIL_SCREEN_REGISTRY, MailScreen, MailScreenId, MailScreenMsg,
    PlaceholderScreen, dashboard::DashboardScreen, messages::MessageBrowserScreen, screen_meta,
    system_health::SystemHealthScreen, timeline::TimelineScreen,
};

/// How often the TUI ticks (100 ms ≈ 10 fps).
const TICK_INTERVAL: Duration = Duration::from_millis(100);

const PALETTE_MAX_VISIBLE: usize = 12;
const PALETTE_DYNAMIC_AGENT_CAP: usize = 50;
const PALETTE_DYNAMIC_THREAD_CAP: usize = 50;
const PALETTE_DYNAMIC_TOOL_CAP: usize = 50;
const PALETTE_DYNAMIC_EVENT_SCAN: usize = 1500;

// ──────────────────────────────────────────────────────────────────────
// MailMsg — top-level message type
// ──────────────────────────────────────────────────────────────────────

/// Top-level message type for the TUI application.
#[derive(Debug, Clone)]
pub enum MailMsg {
    /// Terminal event (keyboard, mouse, resize, tick).
    Terminal(Event),
    /// Forwarded screen-level message.
    Screen(MailScreenMsg),
    /// Switch to a specific screen.
    SwitchScreen(MailScreenId),
    /// Toggle the help overlay.
    ToggleHelp,
    /// Request application quit.
    Quit,
}

impl From<Event> for MailMsg {
    fn from(event: Event) -> Self {
        Self::Terminal(event)
    }
}

// ──────────────────────────────────────────────────────────────────────
// MailAppModel — implements ftui_runtime::Model
// ──────────────────────────────────────────────────────────────────────

/// The top-level TUI application model.
///
/// Owns all screen instances and dispatches events to the active screen
/// after processing global keybindings.
pub struct MailAppModel {
    state: Arc<TuiSharedState>,
    active_screen: MailScreenId,
    screens: HashMap<MailScreenId, Box<dyn MailScreen>>,
    help_visible: bool,
    command_palette: CommandPalette,
    tick_count: u64,
}

impl MailAppModel {
    /// Create a new application model with placeholder screens.
    #[must_use]
    pub fn new(state: Arc<TuiSharedState>) -> Self {
        let mut screens: HashMap<MailScreenId, Box<dyn MailScreen>> = HashMap::new();
        for &id in ALL_SCREEN_IDS {
            if id == MailScreenId::Dashboard {
                screens.insert(id, Box::new(DashboardScreen::new()));
            } else if id == MailScreenId::Messages {
                screens.insert(id, Box::new(MessageBrowserScreen::new()));
            } else if id == MailScreenId::Threads {
                screens.insert(id, Box::new(TimelineScreen::new()));
            } else if id == MailScreenId::SystemHealth {
                screens.insert(id, Box::new(SystemHealthScreen::new(Arc::clone(&state))));
            } else {
                screens.insert(id, Box::new(PlaceholderScreen::new(id)));
            }
        }
        let mut command_palette = CommandPalette::new().with_max_visible(PALETTE_MAX_VISIBLE);
        command_palette.replace_actions(build_palette_actions_static());
        Self {
            state,
            active_screen: MailScreenId::Dashboard,
            screens,
            help_visible: false,
            command_palette,
            tick_count: 0,
        }
    }

    /// Replace a screen implementation (used when real screens are ready).
    pub fn set_screen(&mut self, id: MailScreenId, screen: Box<dyn MailScreen>) {
        self.screens.insert(id, screen);
    }

    /// Get the currently active screen ID.
    #[must_use]
    pub const fn active_screen(&self) -> MailScreenId {
        self.active_screen
    }

    /// Whether the help overlay is currently shown.
    #[must_use]
    pub const fn help_visible(&self) -> bool {
        self.help_visible
    }

    /// Whether the active screen is consuming text input.
    fn consumes_text_input(&self) -> bool {
        if self.command_palette.is_visible() {
            return true;
        }
        self.screens
            .get(&self.active_screen)
            .is_some_and(|s| s.consumes_text_input())
    }

    fn open_palette(&mut self) {
        self.help_visible = false;
        self.command_palette
            .replace_actions(build_palette_actions(&self.state));
        self.command_palette.open();
    }

    fn dispatch_palette_action(&mut self, id: &str) -> Cmd<MailMsg> {
        // ── App controls ───────────────────────────────────────────
        match id {
            palette_action_ids::APP_TOGGLE_HELP => {
                self.help_visible = !self.help_visible;
                return Cmd::none();
            }
            palette_action_ids::APP_QUIT => {
                self.state.request_shutdown();
                return Cmd::quit();
            }
            _ => {}
        }

        // ── Screen navigation ─────────────────────────────────────
        if let Some(screen_id) = screen_from_palette_action_id(id) {
            self.active_screen = screen_id;
            return Cmd::none();
        }

        // ── Dynamic sources ───────────────────────────────────────
        if id.starts_with(palette_action_ids::AGENT_PREFIX) {
            self.active_screen = MailScreenId::Agents;
            return Cmd::none();
        }
        if id.starts_with(palette_action_ids::THREAD_PREFIX) {
            self.active_screen = MailScreenId::Threads;
            return Cmd::none();
        }
        if id.starts_with(palette_action_ids::TOOL_PREFIX) {
            self.active_screen = MailScreenId::ToolMetrics;
            return Cmd::none();
        }

        Cmd::none()
    }
}

impl Model for MailAppModel {
    type Message = MailMsg;

    fn init(&mut self) -> Cmd<Self::Message> {
        Cmd::tick(TICK_INTERVAL)
    }

    fn update(&mut self, msg: Self::Message) -> Cmd<Self::Message> {
        match msg {
            // ── Tick ────────────────────────────────────────────────
            MailMsg::Terminal(Event::Tick) => {
                self.tick_count += 1;
                for screen in self.screens.values_mut() {
                    screen.tick(self.tick_count, &self.state);
                }
                Cmd::tick(TICK_INTERVAL)
            }

            // ── Terminal events (key, mouse, resize, etc.) ─────────
            MailMsg::Terminal(ref event) => {
                // When the command palette is visible, route all events to it first.
                if self.command_palette.is_visible() {
                    if let Some(action) = self.command_palette.handle_event(event) {
                        match action {
                            PaletteAction::Execute(id) => return self.dispatch_palette_action(&id),
                            PaletteAction::Dismiss => {}
                        }
                    }
                    return Cmd::none();
                }

                // Global keybindings (checked before screen dispatch)
                if let Event::Key(key) = event {
                    if key.kind == KeyEventKind::Press {
                        let text_mode = self.consumes_text_input();
                        let is_ctrl_p = key.modifiers.contains(Modifiers::CTRL)
                            && matches!(key.code, KeyCode::Char('p'));
                        if (is_ctrl_p || matches!(key.code, KeyCode::Char(':'))) && !text_mode {
                            self.open_palette();
                            return Cmd::none();
                        }
                        match key.code {
                            KeyCode::Char('q') if !text_mode => {
                                self.state.request_shutdown();
                                return Cmd::quit();
                            }
                            KeyCode::Char('?') if !text_mode => {
                                self.help_visible = !self.help_visible;
                                return Cmd::none();
                            }
                            KeyCode::Tab => {
                                self.active_screen = self.active_screen.next();
                                return Cmd::none();
                            }
                            KeyCode::BackTab => {
                                self.active_screen = self.active_screen.prev();
                                return Cmd::none();
                            }
                            KeyCode::Escape if self.help_visible => {
                                self.help_visible = false;
                                return Cmd::none();
                            }
                            KeyCode::Char(c) if c.is_ascii_digit() && !text_mode => {
                                let n = c.to_digit(10).unwrap_or(0) as usize;
                                if let Some(id) = MailScreenId::from_number(n) {
                                    self.active_screen = id;
                                    return Cmd::none();
                                }
                            }
                            _ => {}
                        }
                    }
                }

                // Forward unhandled events to the active screen
                if let Some(screen) = self.screens.get_mut(&self.active_screen) {
                    map_screen_cmd(screen.update(event, &self.state))
                } else {
                    Cmd::none()
                }
            }

            // ── Screen messages / direct navigation ─────────────────
            MailMsg::Screen(MailScreenMsg::Navigate(id)) | MailMsg::SwitchScreen(id) => {
                self.active_screen = id;
                Cmd::none()
            }
            MailMsg::Screen(MailScreenMsg::Noop) => Cmd::none(),
            MailMsg::Screen(MailScreenMsg::DeepLink(ref target)) => {
                // Route deep-link to the appropriate screen.
                use crate::tui_screens::DeepLinkTarget;
                let target_screen = match target {
                    DeepLinkTarget::TimelineAtTime(_) | DeepLinkTarget::ThreadById(_) => {
                        MailScreenId::Threads
                    }
                    DeepLinkTarget::MessageById(_) => MailScreenId::Messages,
                };
                self.active_screen = target_screen;
                if let Some(screen) = self.screens.get_mut(&target_screen) {
                    screen.receive_deep_link(target);
                }
                Cmd::none()
            }
            MailMsg::ToggleHelp => {
                self.help_visible = !self.help_visible;
                Cmd::none()
            }
            MailMsg::Quit => {
                self.state.request_shutdown();
                Cmd::quit()
            }
        }
    }

    fn view(&self, frame: &mut Frame) {
        use crate::tui_chrome;

        let area = Rect::new(0, 0, frame.width(), frame.height());
        let chrome = tui_chrome::chrome_layout(area);

        // 1. Tab bar (z=1)
        tui_chrome::render_tab_bar(self.active_screen, frame, chrome.tab_bar);

        // 2. Screen content (z=2)
        if let Some(screen) = self.screens.get(&self.active_screen) {
            screen.view(frame, chrome.content, &self.state);
        }

        // 3. Status line (z=3)
        tui_chrome::render_status_line(
            &self.state,
            self.active_screen,
            self.help_visible,
            frame,
            chrome.status_line,
        );

        // 4. Command palette (z=4, modal)
        if self.command_palette.is_visible() {
            self.command_palette.render(area, frame);
        }

        // 5. Help overlay (z=5, topmost)
        if self.help_visible {
            let bindings = self
                .screens
                .get(&self.active_screen)
                .map(|s| s.keybindings())
                .unwrap_or_default();
            tui_chrome::render_help_overlay(self.active_screen, &bindings, frame, area);
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Cmd mapping helper
// ──────────────────────────────────────────────────────────────────────

/// Map a `Cmd<MailScreenMsg>` into a `Cmd<MailMsg>`.
fn map_screen_cmd(cmd: Cmd<MailScreenMsg>) -> Cmd<MailMsg> {
    match cmd {
        Cmd::None => Cmd::none(),
        Cmd::Quit => Cmd::quit(),
        Cmd::Msg(m) => Cmd::msg(MailMsg::Screen(m)),
        Cmd::Tick(d) => Cmd::tick(d),
        Cmd::Log(s) => Cmd::log(s),
        Cmd::Batch(cmds) => Cmd::batch(cmds.into_iter().map(map_screen_cmd).collect()),
        Cmd::Sequence(cmds) => Cmd::sequence(cmds.into_iter().map(map_screen_cmd).collect()),
        Cmd::SaveState => Cmd::save_state(),
        Cmd::RestoreState => Cmd::restore_state(),
        Cmd::SetMouseCapture(b) => Cmd::set_mouse_capture(b),
        Cmd::Task(spec, f) => Cmd::Task(spec, Box::new(move || MailMsg::Screen(f()))),
    }
}

// ──────────────────────────────────────────────────────────────────────
// Command palette catalog
// ──────────────────────────────────────────────────────────────────────

mod palette_action_ids {
    pub const APP_TOGGLE_HELP: &str = "app:toggle_help";
    pub const APP_QUIT: &str = "app:quit";

    pub const AGENT_PREFIX: &str = "agent:";
    pub const THREAD_PREFIX: &str = "thread:";
    pub const TOOL_PREFIX: &str = "tool:";

    pub const SCREEN_DASHBOARD: &str = "screen:dashboard";
    pub const SCREEN_MESSAGES: &str = "screen:messages";
    pub const SCREEN_THREADS: &str = "screen:threads";
    pub const SCREEN_AGENTS: &str = "screen:agents";
    pub const SCREEN_RESERVATIONS: &str = "screen:reservations";
    pub const SCREEN_TOOL_METRICS: &str = "screen:tool_metrics";
    pub const SCREEN_SYSTEM_HEALTH: &str = "screen:system_health";
}

fn screen_from_palette_action_id(id: &str) -> Option<MailScreenId> {
    match id {
        palette_action_ids::SCREEN_DASHBOARD => Some(MailScreenId::Dashboard),
        palette_action_ids::SCREEN_MESSAGES => Some(MailScreenId::Messages),
        palette_action_ids::SCREEN_THREADS => Some(MailScreenId::Threads),
        palette_action_ids::SCREEN_AGENTS => Some(MailScreenId::Agents),
        palette_action_ids::SCREEN_RESERVATIONS => Some(MailScreenId::Reservations),
        palette_action_ids::SCREEN_TOOL_METRICS => Some(MailScreenId::ToolMetrics),
        palette_action_ids::SCREEN_SYSTEM_HEALTH => Some(MailScreenId::SystemHealth),
        _ => None,
    }
}

const fn screen_palette_action_id(id: MailScreenId) -> &'static str {
    match id {
        MailScreenId::Dashboard => palette_action_ids::SCREEN_DASHBOARD,
        MailScreenId::Messages => palette_action_ids::SCREEN_MESSAGES,
        MailScreenId::Threads => palette_action_ids::SCREEN_THREADS,
        MailScreenId::Agents => palette_action_ids::SCREEN_AGENTS,
        MailScreenId::Reservations => palette_action_ids::SCREEN_RESERVATIONS,
        MailScreenId::ToolMetrics => palette_action_ids::SCREEN_TOOL_METRICS,
        MailScreenId::SystemHealth => palette_action_ids::SCREEN_SYSTEM_HEALTH,
    }
}

fn screen_palette_category(id: MailScreenId) -> &'static str {
    match screen_meta(id).category {
        crate::tui_screens::ScreenCategory::Overview => "Navigate",
        crate::tui_screens::ScreenCategory::Communication => "Communication",
        crate::tui_screens::ScreenCategory::Operations => "Operations",
        crate::tui_screens::ScreenCategory::System => "Diagnostics",
    }
}

#[must_use]
fn build_palette_actions_static() -> Vec<ActionItem> {
    let mut out = Vec::with_capacity(MAIL_SCREEN_REGISTRY.len() + 2);

    for meta in MAIL_SCREEN_REGISTRY {
        out.push(
            ActionItem::new(
                screen_palette_action_id(meta.id),
                format!("Go to {}", meta.title),
            )
            .with_description(meta.description)
            .with_tags(&["screen", "navigate"])
            .with_category(screen_palette_category(meta.id)),
        );
    }

    out.push(
        ActionItem::new(palette_action_ids::APP_TOGGLE_HELP, "Toggle Help Overlay")
            .with_description("Show/hide the keybinding reference")
            .with_tags(&["help", "keys"])
            .with_category("App"),
    );
    out.push(
        ActionItem::new(palette_action_ids::APP_QUIT, "Quit")
            .with_description("Exit AgentMailTUI (requests shutdown)")
            .with_tags(&["quit", "exit"])
            .with_category("App"),
    );

    out
}

#[must_use]
fn build_palette_actions(state: &TuiSharedState) -> Vec<ActionItem> {
    let mut out = build_palette_actions_static();

    // ── Agents (top-N most recently active from DB snapshot) ───────
    if let Some(stats) = state.db_stats_snapshot() {
        for agent in stats
            .agents_list
            .into_iter()
            .take(PALETTE_DYNAMIC_AGENT_CAP)
        {
            let crate::tui_events::AgentSummary {
                name,
                program,
                last_active_ts,
            } = agent;
            let title = format!("Agent: {name}");
            let desc = format!("{program} (last_active_ts: {last_active_ts})");
            out.push(
                ActionItem::new(
                    format!("{}{}", palette_action_ids::AGENT_PREFIX, name),
                    title,
                )
                .with_description(desc)
                .with_tags(&["agent"])
                .with_category("Agents"),
            );
        }
    }

    // ── Threads + tools (from recent MailEvent stream) ─────────────
    let events = state.recent_events(PALETTE_DYNAMIC_EVENT_SCAN);

    let mut threads_seen: HashSet<String> = HashSet::new();
    let mut tools_seen: HashSet<String> = HashSet::new();

    for ev in events.iter().rev() {
        if threads_seen.len() < PALETTE_DYNAMIC_THREAD_CAP {
            if let Some((thread_id, subject)) = extract_thread(ev) {
                if threads_seen.insert(thread_id.to_string()) {
                    out.push(
                        ActionItem::new(
                            format!("{}{}", palette_action_ids::THREAD_PREFIX, thread_id),
                            format!("Thread: {thread_id}"),
                        )
                        .with_description(format!("Latest: {subject}"))
                        .with_tags(&["thread", "messages"])
                        .with_category("Threads"),
                    );
                }
            }
        }

        if tools_seen.len() < PALETTE_DYNAMIC_TOOL_CAP {
            if let Some(tool_name) = extract_tool_name(ev) {
                if tools_seen.insert(tool_name.to_string()) {
                    out.push(
                        ActionItem::new(
                            format!("{}{}", palette_action_ids::TOOL_PREFIX, tool_name),
                            format!("Tool: {tool_name}"),
                        )
                        .with_description("Jump to Tool Metrics screen")
                        .with_tags(&["tool"])
                        .with_category("Tools"),
                    );
                }
            }
        }

        if threads_seen.len() >= PALETTE_DYNAMIC_THREAD_CAP
            && tools_seen.len() >= PALETTE_DYNAMIC_TOOL_CAP
        {
            break;
        }
    }

    out
}

fn extract_tool_name(event: &MailEvent) -> Option<&str> {
    match event {
        MailEvent::ToolCallStart { tool_name, .. } | MailEvent::ToolCallEnd { tool_name, .. } => {
            Some(tool_name)
        }
        _ => None,
    }
}

fn extract_thread(event: &MailEvent) -> Option<(&str, &str)> {
    match event {
        MailEvent::MessageSent {
            thread_id, subject, ..
        }
        | MailEvent::MessageReceived {
            thread_id, subject, ..
        } => Some((thread_id, subject)),
        _ => None,
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui_screens::MailScreenMsg;
    use mcp_agent_mail_core::Config;

    fn test_model() -> MailAppModel {
        let config = Config::default();
        let state = TuiSharedState::new(&config);
        MailAppModel::new(state)
    }

    #[test]
    fn initial_screen_is_dashboard() {
        let model = test_model();
        assert_eq!(model.active_screen(), MailScreenId::Dashboard);
        assert!(!model.help_visible());
    }

    #[test]
    fn switch_screen_updates_active() {
        let mut model = test_model();
        let cmd = model.update(MailMsg::SwitchScreen(MailScreenId::Messages));
        assert_eq!(model.active_screen(), MailScreenId::Messages);
        assert!(matches!(cmd, Cmd::None));
    }

    #[test]
    fn toggle_help() {
        let mut model = test_model();
        assert!(!model.help_visible());
        model.update(MailMsg::ToggleHelp);
        assert!(model.help_visible());
        model.update(MailMsg::ToggleHelp);
        assert!(!model.help_visible());
    }

    #[test]
    fn quit_requests_shutdown() {
        let mut model = test_model();
        let cmd = model.update(MailMsg::Quit);
        assert!(model.state.is_shutdown_requested());
        assert!(matches!(cmd, Cmd::Quit));
    }

    #[test]
    fn screen_navigate_switches() {
        let mut model = test_model();
        model.update(MailMsg::Screen(MailScreenMsg::Navigate(
            MailScreenId::Agents,
        )));
        assert_eq!(model.active_screen(), MailScreenId::Agents);
    }

    #[test]
    fn all_screens_have_instances() {
        let model = test_model();
        for &id in ALL_SCREEN_IDS {
            assert!(model.screens.contains_key(&id));
        }
    }

    #[test]
    fn tick_increments_count() {
        let mut model = test_model();
        model.update(MailMsg::Terminal(Event::Tick));
        assert_eq!(model.tick_count, 1);
        model.update(MailMsg::Terminal(Event::Tick));
        assert_eq!(model.tick_count, 2);
    }

    #[test]
    fn map_screen_cmd_preserves_none() {
        assert!(matches!(map_screen_cmd(Cmd::None), Cmd::None));
    }

    #[test]
    fn map_screen_cmd_preserves_quit() {
        assert!(matches!(map_screen_cmd(Cmd::Quit), Cmd::Quit));
    }

    #[test]
    fn map_screen_cmd_wraps_msg() {
        let cmd = map_screen_cmd(Cmd::Msg(MailScreenMsg::Noop));
        assert!(matches!(
            cmd,
            Cmd::Msg(MailMsg::Screen(MailScreenMsg::Noop))
        ));
    }

    #[test]
    fn noop_screen_msg_is_harmless() {
        let mut model = test_model();
        let prev = model.active_screen();
        let cmd = model.update(MailMsg::Screen(MailScreenMsg::Noop));
        assert_eq!(model.active_screen(), prev);
        assert!(matches!(cmd, Cmd::None));
    }

    #[test]
    fn set_screen_replaces_instance() {
        let mut model = test_model();
        let new_screen = Box::new(PlaceholderScreen::new(MailScreenId::Messages));
        model.set_screen(MailScreenId::Messages, new_screen);
        assert!(model.screens.contains_key(&MailScreenId::Messages));
    }

    #[test]
    fn init_returns_tick() {
        let mut model = test_model();
        let cmd = model.init();
        assert!(matches!(cmd, Cmd::Tick(_)));
    }

    #[test]
    fn palette_opens_on_ctrl_p() {
        let mut model = test_model();
        let event = Event::Key(
            ftui::KeyEvent::new(KeyCode::Char('p')).with_modifiers(ftui::Modifiers::CTRL),
        );
        model.update(MailMsg::Terminal(event));
        assert!(model.command_palette.is_visible());
    }

    #[test]
    fn palette_dismisses_on_escape() {
        let mut model = test_model();
        let open = Event::Key(
            ftui::KeyEvent::new(KeyCode::Char('p')).with_modifiers(ftui::Modifiers::CTRL),
        );
        model.update(MailMsg::Terminal(open));
        assert!(model.command_palette.is_visible());

        let esc = Event::Key(ftui::KeyEvent::new(KeyCode::Escape));
        model.update(MailMsg::Terminal(esc));
        assert!(!model.command_palette.is_visible());
    }

    #[test]
    fn palette_executes_screen_navigation() {
        let mut model = test_model();
        let open = Event::Key(
            ftui::KeyEvent::new(KeyCode::Char('p')).with_modifiers(ftui::Modifiers::CTRL),
        );
        model.update(MailMsg::Terminal(open));

        for ch in "messages".chars() {
            let ev = Event::Key(ftui::KeyEvent::new(KeyCode::Char(ch)));
            model.update(MailMsg::Terminal(ev));
        }

        let enter = Event::Key(ftui::KeyEvent::new(KeyCode::Enter));
        model.update(MailMsg::Terminal(enter));
        assert_eq!(model.active_screen(), MailScreenId::Messages);
        assert!(!model.command_palette.is_visible());
    }

    #[test]
    fn deep_link_timeline_switches_to_threads() {
        use crate::tui_screens::DeepLinkTarget;
        let mut model = test_model();
        assert_eq!(model.active_screen(), MailScreenId::Dashboard);

        model.update(MailMsg::Screen(MailScreenMsg::DeepLink(
            DeepLinkTarget::TimelineAtTime(50_000_000),
        )));
        assert_eq!(model.active_screen(), MailScreenId::Threads);
    }

    #[test]
    fn deep_link_message_switches_to_messages() {
        use crate::tui_screens::DeepLinkTarget;
        let mut model = test_model();

        model.update(MailMsg::Screen(MailScreenMsg::DeepLink(
            DeepLinkTarget::MessageById(42),
        )));
        assert_eq!(model.active_screen(), MailScreenId::Messages);
    }
}
