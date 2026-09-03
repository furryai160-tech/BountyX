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

    pub async fn send_message_with_inline_keyboard(&self, text: &str, inline_keyboard: serde_json::Value) -> Result<()> {
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

        for target_chat in target_chats {
            let payload = json!({
                "chat_id": target_chat,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
                "reply_markup": inline_keyboard
            });

            match self.client.post(&url).json(&payload).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        debug!("Telegram inline notification sent successfully to chat {}", target_chat);
                        if let Some(ref repo) = self.repository {
                            let _ = repo.log_notification("TELEGRAM_V3_REPORT", text).await;
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

    pub async fn notify_v3_report(&self, report: &crate::reporting::generator::BugBountyReport) {
        let max_sev = report.findings.iter().map(|f| &f.risk.severity).max().unwrap_or(&crate::security::risk::Severity::Medium);
        let sev_str = format!("{:?}", max_sev).to_uppercase();
        let sev_badge = match sev_str.as_str() {
            "CRITICAL" => "🚨 حرج (CRITICAL)",
            "HIGH" => "🟠 عالي (HIGH)",
            "MEDIUM" => "🟡 متوسط (MEDIUM)",
            _ => "ℹ️ منخفض / معلوماتي",
        };

        let mut findings_summary = String::new();
        for (i, f) in report.findings.iter().take(4).enumerate() {
            findings_summary.push_str(&format!("{}. <b>{}</b> [<code>{}</code>]\n", i + 1, f.title, f.risk.severity));
        }

        let mut msg = format!(
            "🚨 <b>اكتشاف ثغرة أمنية جديدة عبر BountyX V3!</b>\n\n\
            🎯 <b>الهدف:</b> <code>{}</code>\n\
            ⚠️ <b>درجة الخطورة:</b> <b>{}</b>\n\
            📊 <b>عدد الثغرات المؤكدة:</b> {}\n\n\
            🔬 <b>أبرز الثغرات المكتشفة:</b>\n{}\n\n\
            🛡️ <b>حالة المراجعة:</b> ⚠️ التقرير الكامل مرفق كـ PDF، اضغط الزر أدناه لاعتماده وإرساله فوراً.\n\
            🆔 <b>معرف التقرير:</b> <code>{}</code>",
            report.target_domain,
            sev_badge,
            report.findings.len(),
            findings_summary.trim_end(),
            report.id
        );

        if msg.len() > 1020 {
            msg.truncate(1015);
            msg.push_str("...");
        }

        let inline_keyboard = serde_json::json!({
            "inline_keyboard": [
                [
                    {
                        "text": "🚀 إرسال واعتماد التقرير (Submit Report)",
                        "callback_data": format!("approve:{}", report.id)
                    }
                ],
                [
                    {
                        "text": "❌ استبعاد ورفض",
                        "callback_data": format!("reject:{}", report.id)
                    }
                ]
            ]
        });

        // 1. Compile professional PDF report
        let safe_domain = report.target_domain.replace(['/', ':', '.'], "_");
        let pdf_dir = std::path::Path::new("reports");
        tokio::fs::create_dir_all(pdf_dir).await.ok();
        let pdf_path = pdf_dir.join(format!("{}-v3-assessment.pdf", safe_domain));

        let mut sent_as_document = false;
        if let Ok(_) = crate::reporting::pdf::PdfReportGenerator::generate_pdf(report, &pdf_path).await {
            let file_name = format!("{}_Security_Report.pdf", safe_domain);
            if let Ok(true) = self.send_document_with_inline_keyboard(
                &pdf_path.to_string_lossy(),
                &file_name,
                &msg,
                inline_keyboard.clone()
            ).await {
                sent_as_document = true;
            }
        }

        // 2. Fallback: if document sending was skipped or failed, send formatted text message with buttons
        if !sent_as_document {
            let _ = self.send_message_with_inline_keyboard(&msg, inline_keyboard).await;
        }
    }

    pub async fn send_document_with_inline_keyboard(
        &self,
        file_path: &str,
        file_name: &str,
        caption: &str,
        inline_keyboard: serde_json::Value,
    ) -> Result<bool> {
        if !self.enabled {
            return Ok(false);
        }

        let file_bytes = match tokio::fs::read(file_path).await {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Failed to read PDF file for Telegram upload {}: {}", file_path, e);
                return Ok(false);
            }
        };

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
            return Ok(false);
        }

        let url = format!(
            "https://api.telegram.org/bot{}/sendDocument",
            self.bot_token
        );

        let mut sent_any = false;
        for target_chat in target_chats {
            let part = match reqwest::multipart::Part::bytes(file_bytes.clone())
                .file_name(file_name.to_string())
                .mime_str("application/pdf")
            {
                Ok(p) => p,
                Err(e) => {
                    warn!("Failed to construct multipart PDF: {}", e);
                    continue;
                }
            };

            let form = reqwest::multipart::Form::new()
                .text("chat_id", target_chat.to_string())
                .text("caption", caption.to_string())
                .text("parse_mode", "HTML")
                .text("reply_markup", inline_keyboard.to_string())
                .part("document", part);

            match self.client.post(&url).multipart(form).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        debug!("Telegram unified PDF + text + buttons sent successfully to chat {}", target_chat);
                        sent_any = true;
                    } else {
                        let err_body = resp.text().await.unwrap_or_default();
                        warn!("Telegram sendDocument returned non-success for chat {}: {}", target_chat, err_body);
                    }
                }
                Err(e) => {
                    error!("Failed to send Telegram PDF document to chat {}: {}", target_chat, e);
                }
            }
        }

        Ok(sent_any)
    }


    pub async fn send_document(&self, file_path: &str, file_name: &str, caption: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let file_bytes = match tokio::fs::read(file_path).await {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Failed to read PDF file for Telegram upload {}: {}", file_path, e);
                return Ok(());
            }
        };

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

        let url = format!(
            "https://api.telegram.org/bot{}/sendDocument",
            self.bot_token
        );

        for target_chat in target_chats {
            let part = match reqwest::multipart::Part::bytes(file_bytes.clone())
                .file_name(file_name.to_string())
                .mime_str("application/pdf")
            {
                Ok(p) => p,
                Err(e) => {
                    warn!("Failed to construct multipart PDF: {}", e);
                    continue;
                }
            };

            let form = reqwest::multipart::Form::new()
                .text("chat_id", target_chat.to_string())
                .text("caption", caption.to_string())
                .text("parse_mode", "HTML")
                .part("document", part);

            match self.client.post(&url).multipart(form).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        debug!("Telegram PDF document sent successfully to chat {}", target_chat);
                    } else {
                        let err_body = resp.text().await.unwrap_or_default();
                        warn!("Telegram sendDocument returned non-success for chat {}: {}", target_chat, err_body);
                    }
                }
                Err(e) => {
                    error!("Failed to send Telegram PDF document to chat {}: {}", target_chat, e);
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
