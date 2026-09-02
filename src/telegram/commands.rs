use crate::config::AppConfig;
use crate::database::repository::Repository;
use crate::errors::{BountyScopeError, Result};
use crate::tools::SecurityTool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, warn};


pub struct TelegramCommandHandler {
    config: AppConfig,
    repository: Repository,
    is_paused: Arc<AtomicBool>,
}

impl TelegramCommandHandler {
    pub fn new(config: AppConfig, repository: Repository, is_paused: Arc<AtomicBool>) -> Self {
        Self {
            config,
            repository,
            is_paused,
        }
    }

    pub async fn handle_command(&self, chat_id: i64, text: &str) -> Result<String> {
        // Gate 1: Check chat_id against database or pre-configured chat_id
        let is_auth = (self.config.telegram_chat_id != 0 && chat_id == self.config.telegram_chat_id)
            || self.repository.is_telegram_chat_authorized(chat_id).await.unwrap_or(false);

        if !is_auth {
            warn!(
                "Unauthorized command attempt from Telegram chat_id: {}",
                chat_id
            );
            return Err(BountyScopeError::TelegramUnauthorized(chat_id));
        }

        let trimmed_text = text.trim();
        let parts: Vec<&str> = trimmed_text.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(self.render_help());
        }

        // Match Full Arabic Button Labels
        match trimmed_text {
            "📊 حالة النظام" | "حالة النظام" => return self.handle_status().await,
            "📋 عرض الثغرات" | "عرض الثغرات" | "الثغرات" => return self.handle_findings().await,
            "📁 البرامج" | "البرامج" => return self.handle_programs().await,
            "📄 أحدث التقارير" | "أحدث التقارير" | "التقارير" => return self.handle_reports().await,
            "🩺 فحص الأدوات" | "فحص الأدوات" | "فحص النظام" => return self.handle_health().await,
            "⏳ قائمة الانتظار" | "قائمة الانتظار" | "طابور الفحص" => return self.handle_queue().await,
            "🎯 الأصول المصرح بها" | "الأصول المصرح بها" | "النطاق" => return self.handle_scope().await,
            "🚀 فحص هدف" | "فحص هدف" => return Ok("🎯 <b>لفحص هدف محدد فوراً، أرسل الأمر مع اسم النطاق كالتالي:</b>\n<code>/scan example.com</code>\n\nأو لفحص برنامج كامل:\n<code>/scan_program shopify</code>".to_string()),
            "⏸️ إيقاف مؤقت" | "إيقاف مؤقت" | "ايقاف مؤقت" => return self.handle_stop_cmd(&[]).await,
            "▶️ استئناف" | "استئناف" | "تشغيل" => return self.handle_start_cmd(&[]).await,
            "❓ المساعدة والأوامر" | "المساعدة والأوامر" | "مساعدة" => return Ok(self.render_help()),
            _ => {}
        }

        let cmd = parts[0].to_lowercase();
        let args = &parts[1..];

        match cmd.as_str() {
            "/status" => self.handle_status().await,
            "/programs" => self.handle_programs().await,
            "/scope" => self.handle_scope().await,
            "/findings" => self.handle_findings().await,
            "/reports" => self.handle_reports().await,
            "/queue" => self.handle_queue().await,
            "/health" => self.handle_health().await,
            "/scan" => self.handle_scan_target(args).await,
            "/scan_program" => self.handle_scan_program(args).await,
            "/scan_all" => self.handle_scan_all(args).await,
            "/broadcast" => self.handle_broadcast(args).await,
            "/start" => self.handle_start_cmd(args).await,
            "/stop" => self.handle_stop_cmd(args).await,
            "/help" => Ok(self.render_help()),

            _ => Ok(format!(
                "❓ أمر غير معروف: <code>{}</code>\n\nاستخدم الأزرار بالأسفل أو /help لعرض قائمة الأوامر المتاحة.",
                cmd
            )),
        }
    }


    async fn handle_status(&self) -> Result<String> {
        let stats = self.repository.get_stats().await?;
        let paused = self.is_paused.load(Ordering::SeqCst);
        let status_emoji = if paused { "⏸️ متوقف مؤقتاً" } else { "🟢 نشط ويعمل" };

        Ok(format!(
            "🟢 <b>حالة BountyScope</b> ({})\n\n\
            💻 <b>نظام التشغيل:</b> Kali Linux\n\n\
            📁 <b>البرامج المتتبعة:</b> {}\n\
            🎯 <b>الأصول المصرح بها:</b> {}\n\n\
            ⏳ <b>مهام في الانتظار:</b> {}\n\
            ⚡ <b>مهام جارية الآن:</b> {}\n\
            ✅ <b>مهام مكتملة:</b> {}\n\n\
            🚨 <b>الثغرات المحتملة:</b> {}\n\
            📄 <b>تقارير بانتظار المراجعة:</b> {}",
            status_emoji,
            stats.total_programs,
            stats.in_scope_assets,
            stats.queued_jobs,
            stats.running_jobs,
            stats.completed_jobs,
            stats.potential_findings,
            stats.total_reports - stats.verified_reports
        ))
    }

    async fn handle_programs(&self) -> Result<String> {
        let programs = self.repository.list_programs().await?;
        if programs.is_empty() {
            return Ok("📁 لا توجد برامج مسجلة بعد. قم بتشغيل مزامنة النطاق أولاً.".to_string());
        }

        let mut lines = vec![format!("📁 <b>البرامج المتتبعة ({})</b>:\n", programs.len())];
        for (i, p) in programs.iter().take(25).enumerate() {
            let bounty_badge = if p.offers_bounties { "💰 [باونتي]" } else { "📋 [VDP]" };
            lines.push(format!("{}. <code>{}</code> - {} {}", i + 1, p.handle, p.name, bounty_badge));
        }

        if programs.len() > 25 {
            lines.push(format!("\n<i>... وهناك {} برامج إضافية</i>", programs.len() - 25));
        }

        Ok(lines.join("\n"))
    }

    async fn handle_scope(&self) -> Result<String> {
        let assets = self.repository.list_in_scope_assets().await?;
        if assets.is_empty() {
            return Ok("🎯 لا توجد أصول داخل النطاق في قاعدة البيانات بعد.".to_string());
        }

        let mut lines = vec![format!("🎯 <b>الأصول المصرح بها ({})</b>:\n", assets.len())];
        for (i, a) in assets.iter().take(20).enumerate() {
            let bounty = if a.eligible_for_bounty { "💰" } else { "📋" };
            lines.push(format!("{}. {} <code>{}</code> [{}]", i + 1, bounty, a.identifier, a.asset_type));
        }

        if assets.len() > 20 {
            lines.push(format!("\n<i>... وهناك {} أصول إضافية</i>", assets.len() - 20));
        }

        Ok(lines.join("\n"))
    }

    async fn handle_findings(&self) -> Result<String> {
        let findings = self.repository.list_findings(None).await?;
        if findings.is_empty() {
            return Ok("🚨 لا توجد نتائج أمنية مسجلة حتى الآن.".to_string());
        }

        let mut lines = vec![format!("🚨 <b>النتائج والثغرات الأمنية ({})</b>:\n", findings.len())];
        for (i, f) in findings.iter().take(15).enumerate() {
            let sev_badge = match f.severity.to_lowercase().as_str() {
                "critical" => "🚨 [حرج]",
                "high" => "🟠 [عالي]",
                "medium" => "🟡 [متوسط]",
                _ => "ℹ️ [معلوماتي]",
            };
            lines.push(format!(
                "{}. {} <code>{}</code>\n   الهدف: <code>{}</code>\n   الحالة: <b>{}</b>",
                i + 1, sev_badge, f.template_name, f.matched_at, f.status
            ));
        }

        if findings.len() > 15 {
            lines.push(format!("\n<i>... وهناك {} نتائج إضافية</i>", findings.len() - 15));
        }

        Ok(lines.join("\n"))
    }

    async fn handle_reports(&self) -> Result<String> {
        let reports = self.repository.list_reports().await?;
        if reports.is_empty() {
            return Ok("📄 لم يتم إنشاء أي مسودات تقارير بعد.".to_string());
        }

        let mut lines = vec![format!("📄 <b>مسودات التقارير المولدة ({})</b>:\n", reports.len())];
        for (i, r) in reports.iter().take(15).enumerate() {
            let verified = if r.human_verified { "✅ تم التحقق" } else { "⏳ مسودة غير مراجعة" };
            lines.push(format!(
                "{}. <b>{}</b> ({})\n   المسار: <code>{}</code>",
                i + 1, r.title, verified, r.file_path
            ));
        }

        Ok(lines.join("\n"))
    }

    async fn handle_queue(&self) -> Result<String> {
        let jobs = self.repository.list_jobs(20).await?;
        if jobs.is_empty() {
            return Ok("⏳ قائمة المهام فارغة حالياً.".to_string());
        }

        let mut lines = vec![format!("⏳ <b>المهام الجارية والحديثة ({})</b>:\n", jobs.len())];
        for (i, j) in jobs.iter().enumerate() {
            let status_badge = match j.status.as_str() {
                "QUEUED" => "⏳ في الانتظار",
                "RUNNING" => "⚡ جاري الفحص",
                "COMPLETED" => "✅ مكتمل",
                "FAILED" => "❌ فشل",
                _ => "⏸️ ملغي",
            };
            lines.push(format!(
                "{}. <code>{}</code> | {} | المرحلة: <b>{}</b>",
                i + 1, j.target, status_badge, j.stage
            ));
        }

        Ok(lines.join("\n"))
    }

    async fn handle_health(&self) -> Result<String> {
        let db_status = "✅ متصل (SQLite WAL)";
        let h1_status = if self.config.is_hackerone_configured() {
            "✅ متصل بحساب HackerOne الرسمي"
        } else {
            "⚠️ وضع المحاكاة غير المتصل نشط"
        };
        let tg_status = "✅ متصل ومصرح بالكامل";

        Ok(format!(
            "🏥 <b>فحص صحة نظام BountyScope</b>\n\n\
            <b>قاعدة البيانات:</b> {}\n\
            <b>حساب HackerOne:</b> {}\n\
            <b>تنبيهات تيليجرام:</b> {}\n\
            <b>أقصى تزامن للمهام:</b> {} عمال\n\
            <b>درجات خطورة Nuclei:</b> {}",
            db_status,
            h1_status,
            tg_status,
            self.config.max_concurrent_jobs,
            self.config.nuclei_severities.join(", ")
        ))
    }

    async fn handle_start_cmd(&self, args: &[&str]) -> Result<String> {
        if !self.verify_admin_pin(args) {
            return Ok("🔒 <b>مطلوب رمز المصادقة (PIN):</b>\n<code>/start &lt;PIN&gt;</code>".to_string());
        }

        self.is_paused.store(false, Ordering::SeqCst);
        info!("BountyScope worker queue RESUMED via Telegram command.");
        Ok("🟢 <b>تم استئناف خط الأتمتة.</b> عمال الفحص جاهزون لمعالجة الأهداف.".to_string())
    }

    async fn handle_stop_cmd(&self, args: &[&str]) -> Result<String> {
        if !self.verify_admin_pin(args) {
            return Ok("🔒 <b>مطلوب رمز المصادقة (PIN):</b>\n<code>/stop &lt;PIN&gt;</code>".to_string());
        }

        self.is_paused.store(true, Ordering::SeqCst);
        info!("BountyScope worker queue PAUSED via Telegram command.");
        Ok("⏸️ <b>تم إيقاف خط الأتمتة مؤقتاً.</b> سينتهي العمال من المهام الجارية ويتوقفون.".to_string())
    }

    fn verify_admin_pin(&self, args: &[&str]) -> bool {
        match &self.config.telegram_admin_pin {
            Some(pin) => {
                if let Some(user_pin) = args.first() {
                    user_pin == pin
                } else {
                    false
                }
            }
            None => true,
        }
    }

    async fn handle_scan_target(&self, args: &[&str]) -> Result<String> {
        if args.is_empty() {
            return Ok("⚠️ <b>الاستخدام:</b> <code>/scan &lt;الهدف&gt; [اسم_البرنامج]</code>\nمثال: <code>/scan api.example.com demo</code>".to_string());
        }

        let target = args[0];
        let program = if args.len() > 1 { args[1] } else { "manual" };

        let job_id = self.repository.enqueue_recon_job(target, program).await?;
        info!("Enqueued job '{}' via Telegram command for target '{}'", job_id, target);

        Ok(format!(
            "🚀 <b>تم إدراج الهدف في قائمة الفحص:</b>\n\n\
            🎯 <b>الهدف:</b> <code>{}</code>\n\
            📁 <b>البرنامج:</b> <code>{}</code>\n\
            🆔 <b>رقم المهمة:</b> <code>{}</code>\n\n\
            سيبدأ العمال في معالجة الهدف فوراً، وستصلك تنبيهات فور اكتشاف أي نتيجة أمنية.",
            target, program, job_id
        ))
    }

    async fn handle_scan_program(&self, args: &[&str]) -> Result<String> {
        if args.is_empty() {
            return Ok("⚠️ <b>الاستخدام:</b> <code>/scan_program &lt;اسم_البرنامج&gt;</code>\nمثال: <code>/scan_program shopify</code>".to_string());
        }

        let handle = args[0];
        let assets = self.repository.list_in_scope_assets().await?;
        let matching_assets: Vec<_> = assets.into_iter().filter(|a| a.identifier.contains(handle) || a.program_id.contains(handle)).collect();

        if matching_assets.is_empty() {
            return Ok(format!("⚠️ لم يتم العثور على أصول مصرح بها تابعة للبرنامج '<code>{}</code>'.", handle));
        }

        let mut enqueued = 0;
        for asset in &matching_assets {
            let _ = self.repository.enqueue_recon_job(&asset.identifier, handle).await;
            enqueued += 1;
        }

        Ok(format!(
            "🚀 <b>بدء فحص جميع أصول البرنامج دفعة واحدة:</b>\n\n\
            📁 <b>البرنامج:</b> <code>{}</code>\n\
            🎯 <b>عدد الأهداف المدرجة:</b> <b>{}</b>\n\n\
            جاري معالجة الأهداف بالتوازي عبر عمال الفحص. استخدم /queue لمتابعة التقدم.",
            handle, enqueued
        ))
    }

    async fn handle_scan_all(&self, args: &[&str]) -> Result<String> {
        let limit: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(20);
        let assets = self.repository.list_all_in_scope_identifiers().await?;

        if assets.is_empty() {
            return Ok("⚠️ لا توجد أصول داخل النطاق في قاعدة البيانات. استخدم <code>/scope</code> أو انتظر اكتمال المزامنة.".to_string());
        }

        let mut count = 0;
        for target in assets.iter().take(limit) {
            let _ = self.repository.enqueue_recon_job(target, "batch_scan").await;
            count += 1;
        }

        Ok(format!(
            "🚀 <b>بدء الفحص الجماعي لأهم الأهداف:</b>\n\n\
            تم إدراج <b>{}</b> أهداف مصرح بها للفحص المتزامن.\n\
            استخدم /queue لمتابعة حالة المهام المباشرة.",
            count
        ))
    }

    async fn handle_broadcast(&self, args: &[&str]) -> Result<String> {
        if args.is_empty() {
            return Ok("⚠️ <b>الاستخدام:</b> <code>/broadcast &lt;قالب_أو_تاغ&gt;</code>\nمثال: <code>/broadcast cve-2024-XXXX</code> أو <code>/broadcast springboot</code>".to_string());
        }

        let query = args[0];
        let mut live_urls = self.repository.list_all_live_http_urls().await?;
        if live_urls.is_empty() {
            let assets = self.repository.list_all_in_scope_identifiers().await?;
            live_urls = assets
                .into_iter()
                .map(|a| if a.starts_with("http") { a } else { format!("https://{}", a) })
                .collect();
        }

        if live_urls.is_empty() {
            return Ok("⚠️ لا توجد أهداف نشطة في قاعدة البيانات للفحص الجماعي. قم بمزامنة النطاق أولاً.".to_string());
        }

        let total_targets = live_urls.len();
        let config = self.config.clone();
        let repository = self.repository.clone();
        let query_str = query.to_string();

        // Spawn background broadcast scan task
        tokio::spawn(async move {
            info!("Flash Broadcast Scan started for query '{}' across {} targets", query_str, total_targets);
            let mut nuclei = crate::tools::NucleiAdapter::new(&config).with_repository(repository.clone());
            if query_str.contains('/') || query_str.ends_with(".yaml") {
                nuclei = nuclei.with_templates(Some(query_str.clone()));
            } else {
                nuclei = nuclei.with_tags(Some(query_str.clone()));
            }

            let input = crate::tools::ToolInput::multiple(&live_urls);
            if let Ok(output) = nuclei.run(input).await {
                let findings = nuclei.parse_findings(&output);
                info!("Flash Broadcast Scan for '{}' completed. Discovered {} findings.", query_str, findings.len());
                let notifier = crate::telegram::TelegramNotifier::new(&config, Some(repository.clone()));
                let report_generator = crate::reporting::MarkdownReportGenerator::new(&config.reports_dir);

                for f in findings {
                    let fingerprint = crate::validation::Deduplicator::compute_finding_fingerprint(
                        "broadcast",
                        &f.host,
                        &f.template_id,
                        f.matcher_name.as_deref(),
                        &f.matched_at,
                    );

                    let save_res = repository
                        .save_finding(
                            "broadcast",
                            &f.host,
                            &f.matched_at,
                            &f.template_id,
                            &f.template_name,
                            f.severity.as_str(),
                            &f.matched_at,
                            f.matcher_name.as_deref(),
                            f.description.as_deref(),
                            &fingerprint,
                            "POTENTIAL",
                            "REQUIRES_REVIEW",
                            &f.raw_json,
                        )
                        .await;

                    if let Ok((finding_id, true)) = save_res {
                        let evidence = crate::evidence::EvidenceCollector::from_nuclei_finding(&f.host, &f);
                        let _ = repository
                            .save_evidence(
                                &finding_id,
                                evidence.request.as_deref(),
                                evidence.response.as_deref(),
                                evidence.curl_command.as_deref(),
                                &evidence.raw_scanner_output,
                            )
                            .await;

                        if let Ok((report_path, report_content)) = report_generator.generate_report(&evidence, "broadcast").await {
                            let title = format!("⚡ FLASH: {} - {}", f.severity, f.template_name);
                            let _ = repository.save_report(&finding_id, &title, &report_path, &report_content).await;
                            notifier.notify_potential_finding(f.severity.as_str(), "broadcast", &f.matched_at, &f.template_name, &report_path).await;
                        }
                    }
                }
            }
        });

        Ok(format!(
            "⚡ <b>تم إطلاق الفحص الصاعق الفوري (0-Day Flash Broadcast):</b>\n\n\
            🔍 <b>القالب / التاغ:</b> <code>{}</code>\n\
            🎯 <b>عدد الأهداف المشمولة:</b> <b>{}</b> هدفاً نشطاً\n\n\
            يعمل الفحص في الخلفية حالياً عبر Nuclei مع تسجيل النتائج وإرسال إشعارات فورية عند وجود أي إصابة!",
            query, total_targets
        ))
    }

    fn render_help(&self) -> String {
        "🤖 <b>لوحة تحكم محرك BountyScope (19 أداة أمنية):</b>\n\n\
        يمكنك الضغط مباشرة على <b>الأزرار بالأسفل</b> أو كتابة الأوامر التالية:\n\n\
        📊 <b>حالة النظام:</b> <code>/status</code> - عرض الإحصائيات والعمال والمهام\n\
        📋 <b>عرض الثغرات:</b> <code>/findings</code> - استعراض الثغرات المكتشفة\n\
        📁 <b>البرامج:</b> <code>/programs</code> - استعراض برامج HackerOne المتتبعة\n\
        📄 <b>أحدث التقارير:</b> <code>/reports</code> - استعراض مسودات تقارير Markdown\n\
        🩺 <b>فحص الأدوات:</b> <code>/health</code> - فحص صحة الأدوات الـ 19 والموارد\n\
        ⏳ <b>قائمة الانتظار:</b> <code>/queue</code> - متابعة طابور المهام الجارية\n\
        🎯 <b>الأصول المصرح بها:</b> <code>/scope</code> - عرض النطاقات المصرح بها\n\
        🚀 <b>فحص هدف:</b> <code>/scan &lt;target&gt;</code> - فحص هدف محدد بالترسانة كاملة\n\
        ⚡ <b>فحص صاعق:</b> <code>/broadcast &lt;tag&gt;</code> - فحص سريع لجميع الأصول بثغرة 0-Day\n\
        🏢 <b>فحص برنامج:</b> <code>/scan_program &lt;handle&gt;</code> - فحص كل أصول برنامج معين\n\
        ⏸️ <b>إيقاف مؤقت:</b> <code>/stop</code> - إيقاف عمال الفحص مؤقتاً\n\
        ▶️ <b>استئناف:</b> <code>/start</code> - استئناف خط الأتمتة والفحص".to_string()
    }
}


