use crate::config::AppConfig;
use crate::database::repository::Repository;
use crate::errors::{BountyScopeError, Result};
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use tracing::{debug, error, warn};

#[derive(Clone)]
pub struct TelegramNotifier {
    client: Client,
    bot_token: String,
    chat_id: i64,
    enabled: bool,
    repository: Option<Repository>,
}

impl TelegramNotifier {
    pub fn new(config: &AppConfig, repository: Option<Repository>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        let enabled = config.is_telegram_configured();

        Self {
            client,
            bot_token: config.telegram_bot_token.clone(),
            chat_id: config.telegram_chat_id,
            enabled,
            repository,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub async fn send_message(&self, text: &str) -> Result<()> {
        if !self.enabled {
            debug!("Telegram not configured, skipping notification: {}", text);
            return Ok(());
        }

        let mut target_chats = std::collections::HashSet::new();
        if self.chat_id != 0 {
            target_chats.insert(self.chat_id);
        }

        if let Some(ref repo) = self.repository {
            if let Ok(authorized) = repo.list_authorized_telegram_chats().await {
                for cid in authorized {
                    target_chats.insert(cid);
                }
            }
        }

        if target_chats.is_empty() {
            debug!("No authorized Telegram chat IDs found yet for notification: {}", text);
            return Ok(());
        }

        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.bot_token
        );

        let keyboard = crate::telegram::bot::arabic_control_keyboard();

        for target_chat in target_chats {
            let payload = json!({
                "chat_id": target_chat,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
                "reply_markup": keyboard
            });

            match self.client.post(&url).json(&payload).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        debug!("Telegram notification sent successfully to chat {}", target_chat);
                        if let Some(ref repo) = self.repository {
                            let _ = repo.log_notification("TELEGRAM_ALERT", text).await;
                        }
                    } else {
                        let err_body = resp.text().await.unwrap_or_default();
                        warn!("Telegram sendMessage returned non-success for chat {}: {}", target_chat, err_body);
                    }
                }
                Err(e) => {
                    error!("Failed to send Telegram message to chat {}: {}", target_chat, e);
                }
            }
        }

        Ok(())
    }


    pub async fn notify_startup(&self, programs: usize, assets: usize, workers: usize) {
        let msg = format!(
            "🟢 <b>تم تشغيل BountyScope بنجاح</b>\n\n\
            💻 <b>نظام التشغيل:</b> Kali Linux\n\
            ⚡ <b>المهام المتزامنة:</b> {} عمال (Workers)\n\n\
            📁 <b>البرامج المتتبعة:</b> {}\n\
            🎯 <b>الأصول المصرح بها:</b> {}\n\n\
            ⏳ <b>قائمة الانتظار:</b> 0 مهام",
            workers, programs, assets
        );
        let _ = self.send_message(&msg).await;
    }

    pub async fn notify_new_target(&self, program: &str, target: &str) {
        let msg = format!(
            "🆕 <b>هدف جديد داخل النطاق المصرح</b>\n\n\
            📁 <b>البرنامج:</b>\n<code>{}</code>\n\n\
            🎯 <b>الهدف:</b>\n<code>{}</code>\n\n\
            ⚡ <b>الحالة:</b>\nتم إدراجه في قائمة الفحص والاستكشاف",
            program, target
        );
        let _ = self.send_message(&msg).await;
    }

    pub async fn notify_new_targets_summary(&self, program: &str, count: usize, sample_targets: &[String]) {
        let sample_list = sample_targets
            .iter()
            .take(5)
            .map(|t| format!("• <code>{}</code>", t))
            .collect::<Vec<_>>()
            .join("\n");

        let msg = format!(
            "🆕 <b>اكتشاف أهداف جديدة داخل النطاق ({})</b>\n\n\
            📁 <b>البرنامج:</b>\n<code>{}</code>\n\n\
            🎯 <b>أمثلة على الأهداف:</b>\n{}\n\n\
            ⚡ <b>الحالة:</b>\nتم إدراج جميع الـ {} أهداف في قائمة الفحص التلقائي.",
            count, program, sample_list, count
        );
        let _ = self.send_message(&msg).await;
    }

    pub async fn notify_potential_finding(
        &self,
        severity: &str,
        _program: &str,
        target: &str,
        template: &str,
        report_path: &str,
    ) {
        let sev_badge = match severity.to_lowercase().as_str() {
            "critical" => "🚨 حرج (CRITICAL)",
            "high" => "🟠 عالي (HIGH)",
            "medium" => "🟡 متوسط (MEDIUM)",
            _ => "ℹ️ منخفض / معلوماتي",
        };

        let msg = format!(
            "🚨 <b>اكتشاف ثغرة أمنية محتملة!</b>\n\n\
            ⚠️ <b>درجة الخطورة:</b>\n<b>{}</b>\n\n\
            🎯 <b>الهدف المصاب:</b>\n<code>{}</code>\n\n\
            🔍 <b>القالب / نوع الثغرة:</b>\n<code>{}</code>\n\n\
            🛡️ <b>الحالة:</b>\nتتطلب مراجعة وتحقق بشري (Human-in-the-loop)\n\n\
            📄 <b>مسودة التقرير:</b>\n<code>{}</code>",
            sev_badge, target, template, report_path
        );
        let _ = self.send_message(&msg).await;
    }

    pub async fn notify_report_ready(&self, target: &str, severity: &str, report_path: &str) {
        let sev_badge = match severity.to_lowercase().as_str() {
            "critical" => "🚨 حرج (CRITICAL)",
            "high" => "🟠 عالي (HIGH)",
            "medium" => "🟡 متوسط (MEDIUM)",
            _ => "ℹ️ منخفض",
        };

        let msg = format!(
            "📄 <b>مسودة التقرير جاهزة للمراجعة</b>\n\n\
            🎯 <b>الهدف:</b>\n<code>{}</code>\n\n\
            ⚠️ <b>درجة الخطورة:</b>\n<b>{}</b>\n\n\
            📁 <b>مسار التقرير:</b>\n<code>{}</code>",
            target,
            sev_badge,
            report_path
        );
        let _ = self.send_message(&msg).await;
    }

    pub async fn notify_tool_error(&self, tool: &str, target: &str, error_msg: &str) {
        let msg = format!(
            "⚠️ <b>خطأ أثناء تشغيل أداة الأمان</b>\n\n\
            🛠️ <b>الأداة:</b>\n<code>{}</code>\n\n\
            🎯 <b>الهدف:</b>\n<code>{}</code>\n\n\
            ❌ <b>الخطأ:</b>\n<code>{}</code>",
            tool, target, error_msg
        );
        let _ = self.send_message(&msg).await;
    }

    pub async fn notify_error(&self, component: &str, target: &str, error: &str) {
        self.notify_tool_error(component, target, error).await;
    }
}
