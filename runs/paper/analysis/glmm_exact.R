# Mixed-effects logistic regression of the baseline programs, fitted by maximum likelihood
# (Laplace approximation, lme4::glmer). Replaces the variational fit quoted in report.md.
#
# Usage, from this folder:  Rscript glmm_exact.R        (needs the lme4 package)
# Writes glmm_exact_output.txt and tables/T21_mixed_model.csv.
#
# K is constant within a model x class cell and `recognises` within a model x task cell, so the
# models used in the manuscript carry random intercepts for those cells as well as for model,
# class and task. The fit without the cell-level intercepts is kept for comparison: it treats the
# programs of a cell as independent given model, class and task, and its interval is too narrow.
suppressPackageStartupMessages(library(lme4))
d <- read.csv("model_data.csv")
d$model <- factor(d$model); d$task <- factor(d$task); d$cwe <- factor(d$cwe)
d$cell_mc <- interaction(d$model, d$cwe, drop = TRUE)
d$cell_mt <- interaction(d$model, d$task, drop = TRUE)
ctl <- glmerControl(optimizer = "bobyqa", optCtrl = list(maxfun = 2e5))
SIMPLE <- "(1 | model) + (1 | cwe) + (1 | task)"
FULL   <- paste(SIMPLE, "+ (1 | cell_mc) + (1 | cell_mt)")

rows <- list()
fit <- function(label, term, re, re_label, data, subset_label) {
  m  <- glmer(as.formula(paste("vulnerable ~", term, "+", re)), data = data, family = binomial, control = ctl)
  m0 <- glmer(as.formula(paste("vulnerable ~ 1 +", re)), data = data, family = binomial, control = ctl)
  b <- fixef(m)[term]; se <- sqrt(diag(vcov(m)))[term]; a <- anova(m0, m)
  cat("\n=====", label, "=====\n"); print(summary(m)$coefficients); print(VarCorr(m))
  cat(sprintf("OR = %.3f, Wald 95%% CI %.3f to %.3f, z = %.3f, p = %.4f | LRT chisq = %.3f, p = %.4f | logLik = %.2f | singular: %s\n",
              exp(b), exp(b - 1.96 * se), exp(b + 1.96 * se), b / se, 2 * pnorm(-abs(b / se)), a$Chisq[2], a$`Pr(>Chisq)`[2],
              as.numeric(logLik(m)), isSingular(m)))
  sds <- as.data.frame(VarCorr(m))
  rows[[length(rows) + 1]] <<- data.frame(
    predictor = term, random_intercepts = re_label, programs = subset_label, n = nrow(data),
    odds_ratio = exp(b), ci_lo = exp(b - 1.96 * se), ci_hi = exp(b + 1.96 * se), z = b / se, p = 2 * pnorm(-abs(b / se)),
    lrt_chisq = a$Chisq[2], lrt_p = a$`Pr(>Chisq)`[2], logLik = as.numeric(logLik(m)),
    sd_model = sds$sdcor[sds$grp == "model"], sd_class = sds$sdcor[sds$grp == "cwe"], sd_task = sds$sdcor[sds$grp == "task"],
    sd_model_class = ifelse(any(sds$grp == "cell_mc"), sds$sdcor[sds$grp == "cell_mc"], NA),
    sd_model_task = ifelse(any(sds$grp == "cell_mt"), sds$sdcor[sds$grp == "cell_mt"], NA), row.names = NULL)
  m
}

sink("glmm_exact_output.txt", split = TRUE)
cat("R", as.character(getRversion()), "| lme4", as.character(packageVersion("lme4")), "\n")
cat("programs:", nrow(d), "| vulnerable:", sum(d$vulnerable), "| models:", nlevels(d$model), "| classes:", nlevels(d$cwe),
    "| tasks:", nlevels(d$task), "| model x class cells:", nlevels(d$cell_mc), "| model x task cells:", nlevels(d$cell_mt), "\n")
f <- droplevels(d[d$functional == 1, ])
mA <- fit("K, intercepts for model, class and task", "K_z", SIMPLE, "model, class, task", d, "all")
mB <- fit("K, with cell-level intercepts", "K_z", FULL, "model, class, task, model x class, model x task", d, "all")
cat("\nLRT, cell-level intercepts (K model):\n"); print(anova(mA, mB))
fit("recognises, intercepts for model, class and task", "recognises", SIMPLE, "model, class, task", d, "all")
fit("recognises, with cell-level intercepts", "recognises", FULL, "model, class, task, model x class, model x task", d, "all")
fit("K, with cell-level intercepts, functional programs", "K_z", FULL, "model, class, task, model x class, model x task", f, "functional")
fit("recognises, with cell-level intercepts, functional programs", "recognises", FULL,
    "model, class, task, model x class, model x task", f, "functional")
sink()
write.csv(do.call(rbind, rows), file.path("tables", "T21_mixed_model.csv"), row.names = FALSE)
