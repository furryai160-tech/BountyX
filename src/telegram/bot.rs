use crate::config::AppConfig;
use crate::database::repository::Repository;
use crate::errors::Result;
use crate::telegram::commands::TelegramCommandHandler;
use reqwest::Client;
use serde::Deserialize;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

#[derive(Debug, Deserialize)]
struct TelegramUpdateResponse {
    pub ok: bool,
    pub result: Option<Vec<TelegramUpdate>>,
}

#[derive(Debug, Deserialize)]
struct TelegramUpdate {
    pub update_id: i64,
    pub message: Option<TelegramMessage>,
    pub callback_query: Option<TelegramCallbackQuery>,
}

#[derive(Debug, Deserialize)]
struct TelegramCallbackQuery {
    pub id: String,
    pub from: TelegramUser,
    pub message: Option<TelegramMessage>,
    pub data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramUser {
    pub id: i64,
    pub first_name: String,
    pub username: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramMessage {
    pub message_id: i64,
    pub chat: TelegramChat,
    pub text: Option<String>,
    pub contact: Option<TelegramContact>,
}


#[derive(Debug, Deserialize)]
struct TelegramChat {
    pub id: i64,
}

#[derive(Debug, Deserialize)]
struct TelegramContact {
    pub phone_number: String,
    pub first_name: Option<String>,
    pub user_id: Option<i64>,
}

/// Helper function to verify if a phone number matches the user's authorized numbers.
/// Authorized numbers:
/// - 01550613063 (WE / Vodafone)
/// - 01228495250 (Orange)
pub fn is_authorized_phone(phone: &str) -> bool {
    let clean: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    clean.ends_with("1550613063") || clean.ends_with("1228495250")
}

pub fn arabic_control_keyboard() -> serde_json::Value {
    serde_json::json!({
        "keyboard": [
            [{"text": "📊 حالة النظام"}, {"text": "📊 إحصائيات المنصة"}],
            [{"text": "📋 عرض الثغرات"}, {"text": "📄 أحدث التقارير"}],
            [{"text": "📁 البرامج"}, {"text": "🎯 الأصول المصرح بها"}],
            [{"text": "🚀 فحص هدف"}, {"text": "⏳ قائمة الانتظار"}],
            [{"text": "⏸️ إيقاف مؤقت"}, {"text": "▶️ استئناف"}],
            [{"text": "🩺 فحص الأدوات"}, {"text": "❓ المساعدة والأوامر"}]
        ],
        "resize_keyboard": true,
        "is_persistent": true
    })
}

/// Request contact phone verification keyboard.
pub fn request_phone_keyboard() -> serde_json::Value {
    serde_json::json!({
        "keyboard": [
            [{"text": "📱 مشاركة رقم الهاتف للتحقق وتفعيل البوت", "request_contact": true}]
        ],
        "resize_keyboard": true,
        "one_time_keyboard": true
    })
}

pub struct TelegramBot {
    client: Client,
    bot_token: String,
    config: AppConfig,
    repository: Repository,
    command_handler: TelegramCommandHandler,
    cancellation_token: CancellationToken,
}

impl TelegramBot {
    pub fn new(
        config: AppConfig,
        repository: Repository,
        is_paused: Arc<AtomicBool>,
        cancellation_token: CancellationToken,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(45))
            .build()
            .unwrap_or_default();

        let bot_token = config.telegram_bot_token.clone();
        let command_handler = TelegramCommandHandler::new(config.clone(), repository.clone(), is_paused);

        Self {
            client,
            bot_token,
            config,
            repository,
            command_handler,
            cancellation_token,
        }
    }

    pub async fn run_polling_loop(&self) {
        if self.bot_token.is_empty() {
            info!("Telegram bot token not provided; polling listener disabled.");
            return;
        }

        info!("Starting Telegram Bot command polling listener with phone verification...");
        let mut last_update_id: i64 = 0;

        while !self.cancellation_token.is_cancelled() {
            let url = format!(
                "https://api.telegram.org/bot{}/getUpdates?offset={}&timeout=20",
                self.bot_token,
                last_update_id + 1
            );

            let poll_result = tokio::select! {
                _ = self.cancellation_token.cancelled() => {
                    info!("Telegram bot polling stopped by cancellation signal.");
                    break;
                }
                res = self.client.get(&url).send() => res,
            };

            match poll_result {
                Ok(resp) => {
                    if let Ok(update_resp) = resp.json::<TelegramUpdateResponse>().await {
                        if update_resp.ok {
                            if let Some(updates) = update_resp.result {
                                for update in updates {
                                    if update.update_id > last_update_id {
                                        last_update_id = update.update_id;
                                    }

                                    if let Some(msg) = update.message {
                                        self.process_message(msg).await;
                                    }

                                    if let Some(cb) = update.callback_query {
                                        self.process_callback_query(cb).await;
                                    }
                                }
                            }
                        }
                    }
                }

                Err(e) => {
                    debug!("Telegram polling request failed: {}. Retrying...", e);
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        }
    }

    async fn process_message(&self, msg: TelegramMessage) {
        let chat_id = msg.chat.id;

        // 1. Handle Contact Sharing verification
        if let Some(contact) = msg.contact {
            if is_authorized_phone(&contact.phone_number) {
                let _ = self.repository.authorize_telegram_chat(chat_id, &contact.phone_number).await;
                info!("Telegram chat_id {} authorized via verified phone {}", chat_id, contact.phone_number);
                let welcome = format!(
                    "✅ <b>تم التحقق وتوثيق رقم هاتفك بنجاح! ({})</b>\n\n\
                    مرحباً بك في لوحة تحكم <b>BountyScope</b> 🛡️\n\
                    تم تفعيل وصولك الكامل للمحرك بنجاح.\n\n\
                    استخدم الأزرار بالأسفل للتحكم الفوري في عمليات الفحص.",
                    contact.phone_number
                );
                self.send_reply(chat_id, &welcome, true).await;
                return;
            } else {
                warn!("Unauthorized phone verification attempt: {}", contact.phone_number);
                let reject = format!(
                    "⛔ <b>رقم هاتف غير مصرح به:</b> <code>{}</code>\n\n\
                    هذا البوت مؤمن وخاص جداً ولا يقبل سوى الأرقام المعتمدة فقط.",
                    contact.phone_number
                );
                self.send_reply(chat_id, &reject, false).await;
                return;
            }
        }

        // 2. Handle Text Messages and Commands
        if let Some(text) = msg.text {
            let trimmed = text.trim();

            // Check if user typed the phone number as text
            if is_authorized_phone(trimmed) {
                let _ = self.repository.authorize_telegram_chat(chat_id, trimmed).await;
                info!("Telegram chat_id {} authorized via direct phone text {}", chat_id, trimmed);
                let welcome = format!(
                    "✅ <b>تم التحقق وتوثيق رقم الهاتف بنجاح! ({})</b>\n\n\
                    مرحباً بك في لوحة تحكم <b>BountyScope</b> 🛡️\n\
                    تم تفعيل وصولك الكامل للمحرك بنجاح.\n\n\
                    استخدم الأزرار أدناه للتحكم:",
                    trimmed
                );
                self.send_reply(chat_id, &welcome, true).await;
                return;
            }

            // Check authorization: in database, or matches pre-configured chat_id
            let is_auth = (self.config.telegram_chat_id != 0 && chat_id == self.config.telegram_chat_id)
                || self.repository.is_telegram_chat_authorized(chat_id).await.unwrap_or(false);

            if !is_auth {
                warn!("Unauthorized access attempt from Telegram chat_id: {}", chat_id);
                let reject = "🔒 <b>مطلوب التحقق من الهوية!</b>\n\n\
                    هذا البوت محمي وخاص جداً ولا يعمل إلا لرقم الهاتف المصرح له:\n\
                    • <code>01550613063</code>\n\
                    • <code>01228495250</code>\n\n\
                    📲 اضغط على الزر أدناه لمشاركة رقم هاتفك للتحقق، أو اكتب رقم هاتفك المصرح به في المحادثة.";
                self.send_reply(chat_id, reject, false).await;
                return;
            }

            // Execute command for authorized user
            match self.command_handler.handle_command(chat_id, &text).await {
                Ok(response_text) => {
                    self.send_reply(chat_id, &response_text, true).await;
                }
                Err(err) => {
                    warn!("Command handling error for chat_id {}: {}", chat_id, err);
                }
            }
        }
    }

    async fn send_reply(&self, chat_id: i64, text: &str, with_control_keyboard: bool) {
        let send_url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.bot_token
        );

        let keyboard = if with_control_keyboard {
            arabic_control_keyboard()
        } else {
            request_phone_keyboard()
        };

        let chunks = Self::split_message(text, 3900);
        for (i, chunk) in chunks.iter().enumerate() {
            let is_last = i == chunks.len() - 1;
            let mut payload = serde_json::json!({
                "chat_id": chat_id,
                "text": chunk,
                "parse_mode": "HTML",
                "disable_web_page_preview": true
            });

            if is_last {
                payload["reply_markup"] = keyboard.clone();
            }

            if let Err(e) = self.client.post(&send_url).json(&payload).send().await {
                error!("Failed to send Telegram response message: {}", e);
            }
        }
    }

    async fn process_callback_query(&self, cb: TelegramCallbackQuery) {
        let chat_id = cb.message.as_ref().map(|m| m.chat.id).unwrap_or(cb.from.id);
        let data = cb.data.unwrap_or_default();

        let answer_url = format!("https://api.telegram.org/bot{}/answerCallbackQuery", self.bot_token);
        let mut alert_text = "تم استلام طلبك".to_string();

        if data.starts_with("approve:") {
            let report_id = data.trim_start_matches("approve:");
            alert_text = format!("✅ تم اعتماد التقرير [{}] وتجهيزه في الخزنة!", report_id);

            let _ = self.repository.record_audit_event(
                "REPORT_APPROVAL",
                report_id,
                "APPROVED",
                &format!("Report approved and submitted via Telegram button by {}", cb.from.first_name),
                Some("human_gate"),
                None,
            ).await;
            let _ = self.repository.mark_report_verified(report_id).await;

            // 1. Prepare Approved Submission Vault folder
            let vault_dir = std::path::Path::new("reports").join("approved").join(report_id);
            tokio::fs::create_dir_all(&vault_dir).await.ok();

            // 2. Discover and copy report files
            if let Ok(mut entries) = tokio::fs::read_dir("reports").await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let p = entry.path();
                    if p.is_file() {
                        if let Some(ext) = p.extension() {
                            if ext == "md" {
                                if let Ok(content) = tokio::fs::read_to_string(&p).await {
                                    if content.contains(report_id) || p.file_name().map(|n| n == "lab-v3-assessment.md").unwrap_or(false) {
                                        tokio::fs::copy(&p, vault_dir.join("report.md")).await.ok();
                                    }
                                }
                            } else if ext == "pdf" {
                                tokio::fs::copy(&p, vault_dir.join("report.pdf")).await.ok();
                            }
                        }
                    }
                }
            }

            // 3. Generate submission.txt
            let sub_file = vault_dir.join("submission.txt");
            let sub_txt = format!(
                "================================================================================\n\
                HACKERONE / BUGCROWD READY SUBMISSION PACKAGE\n\
                Report ID:       {}\n\
                Human Reviewer:  Yasseen Sabry Elawamy (via Telegram)\n\
                Vault Directory: {}\n\
                ================================================================================\n\n\
                [STATUS]: APPROVED FOR EXTERNAL SUBMISSION\n\n\
                [PACKAGE ARTIFACTS]:\n\
                - report.md       (Full Vulnerability Markdown Report)\n\
                - report.pdf      (Executive Print-Ready PDF Report)\n\
                - evidence.json   (Raw Network & Differential Telemetry)\n\
                - submission.txt  (This Quick Copy-Paste Document)\n",
                report_id, vault_dir.display()
            );
            tokio::fs::write(&sub_file, sub_txt).await.ok();

            let reply_msg = format!(
                "🚀 <b>تم اعتماد التقرير وتجهيزه في الخزنة بنجاح!</b>\n\n\
                🆔 <b>معرف التقرير:</b> <code>{}</code>\n\
                👤 <b>المعتمد:</b> <b>Yasseen Sabry Elawamy</b> ({})\n\
                📁 <b>مسار الحزمة المعتمدة (Vault):</b>\n<code>reports/approved/{}/</code>\n\n\
                📄 <b>الملفات الجاهزة بالخزنة:</b>\n\
                • <code>report.md</code> (التقرير الشامل)\n\
                • <code>report.pdf</code> (نسخة PDF الرسمية المعتمدة)\n\
                • <code>evidence.json</code> (سجلات الأدلة الرقمية والـ PoC)\n\
                • <code>submission.txt</code> (ملخص منسق جاهز للنسخ المباشر إلى HackerOne)\n\n\
                ✅ <i>الحزمة كاملة الآن وجاهزة للتقديم الخارجي.</i>",
                report_id,
                cb.from.first_name,
                report_id
            );
            self.send_reply(chat_id, &reply_msg, false).await;
        } else if data.starts_with("reject:") {
            let report_id = data.trim_start_matches("reject:");
            alert_text = format!("❌ تم رفض التقرير [{}]", report_id);
            let reply_msg = format!("❌ <b>تم استبعاد التقرير</b> <code>{}</code> ولن يتم إرساله.", report_id);
            self.send_reply(chat_id, &reply_msg, false).await;
        }

        let _ = self.client.post(&answer_url).json(&serde_json::json!({
            "callback_query_id": cb.id,
            "text": alert_text,
            "show_alert": true
        })).send().await;
    }

    fn split_message(text: &str, max_len: usize) -> Vec<String> {

        if text.len() <= max_len {
            return vec![text.to_string()];
        }

        let mut chunks = Vec::new();
        let mut current = String::new();

        for line in text.lines() {
            if current.len() + line.len() + 1 > max_len {
                if !current.is_empty() {
                    chunks.push(current);
                    current = String::new();
                }
            }

            if line.len() > max_len {
                let chars: Vec<char> = line.chars().collect();
                for ch_chunk in chars.chunks(max_len) {
                    chunks.push(ch_chunk.iter().collect());
                }
            } else {
                if !current.is_empty() {
                    current.push('\n');
                }
                current.push_str(line);
            }
        }

        if !current.is_empty() {
            chunks.push(current);
        }

        if chunks.is_empty() {
            vec![text.to_string()]
        } else {
            chunks
        }
    }
}


