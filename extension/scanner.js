(function () {
  const ACTION = {
    ALLOW: "allow",
    WARN: "warn",
    BLOCK: "block"
  };

  const RISK_WEIGHT = {
    Low: 1,
    Medium: 2,
    High: 3,
    Critical: 4
  };

  const RULES = [
    {
      name: "AWS access key",
      category: "Cloud credential",
      pattern: /\bAKIA[0-9A-Z]{16}\b/g,
      risk: "Critical",
      action: ACTION.BLOCK
    },
    {
      name: "AWS secret key",
      category: "Cloud credential",
      pattern: /\baws.{0,24}(secret|private).{0,12}[:=]\s*['"]?[A-Za-z0-9/+=]{32,}/gi,
      risk: "Critical",
      action: ACTION.BLOCK
    },
    {
      name: "OpenAI API key",
      category: "AI provider key",
      pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g,
      risk: "Critical",
      action: ACTION.BLOCK
    },
    {
      name: "API key disclosure",
      category: "API key",
      pattern: /\b(api[_\s-]?key|access[_\s-]?key|client[_\s-]?secret|secret[_\s-]?key)\s*(is|=|:)\s*['"]?[A-Za-z0-9_.\-]{4,}/gi,
      risk: "Critical",
      action: ACTION.BLOCK
    },
    {
      name: "GitHub token",
      category: "Developer token",
      pattern: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
      risk: "Critical",
      action: ACTION.BLOCK
    },
    {
      name: "Private key",
      category: "Private key",
      pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
      risk: "Critical",
      action: ACTION.BLOCK
    },
    {
      name: "JWT token",
      category: "Access token",
      pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
      risk: "Critical",
      action: ACTION.BLOCK
    },
    {
      name: "Password assignment",
      category: "Password",
      pattern: /\b(password|passwd|pwd)\s*[:=]\s*['"]?[^'"\s]{8,}/gi,
      risk: "High",
      action: ACTION.BLOCK
    },
    {
      name: "Password disclosure",
      category: "Password",
      pattern: /\b(my\s+)?(password|passwd|pwd)\s+(is|=|:)\s*['"]?[^'"\s]{4,}/gi,
      risk: "High",
      action: ACTION.BLOCK
    },
    {
      name: "Connection string",
      category: "Database secret",
      pattern: /\b(postgres|postgresql|mysql|mongodb|redis):\/\/[^ \n]+/gi,
      risk: "Critical",
      action: ACTION.BLOCK
    },
    {
      name: "Environment secret",
      category: "Environment secret",
      pattern: /^\s*[A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)[A-Z0-9_]*\s*=\s*.+$/gim,
      risk: "High",
      action: ACTION.BLOCK
    },
    {
      name: "Credit card",
      category: "Payment data",
      pattern: /\b(?:\d[ -]*?){13,19}\b/g,
      risk: "Critical",
      action: ACTION.BLOCK,
      validate: likelyPaymentCard
    },
    {
      name: "Email address",
      category: "PII",
      pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      risk: "Medium",
      action: ACTION.WARN
    },
    {
      name: "Phone number",
      category: "PII",
      pattern: /(?<!\d)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3,5}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}(?!\d)/g,
      risk: "Medium",
      action: ACTION.WARN
    },
    {
      name: "Internal URL",
      category: "Internal system",
      pattern: /\bhttps?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+|[a-z0-9.-]+\.internal)\S*/gi,
      risk: "High",
      action: ACTION.BLOCK
    }
  ];

  function inspectText(text) {
    const findings = [];

    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      let match = rule.pattern.exec(text);
      while (match) {
        const value = match[0];
        if (!rule.validate || rule.validate(value)) {
          findings.push({
            name: rule.name,
            category: rule.category,
            risk: rule.risk,
            action: rule.action,
            preview: mask(value),
            index: match.index
          });
        }
        match = rule.pattern.exec(text);
      }
    }

    for (const token of text.match(/\b[A-Za-z0-9_/\-+=]{28,}\b/g) || []) {
      if (entropy(token) >= 4.25 && !findings.some((finding) => finding.preview.includes(token.slice(0, 3)))) {
        findings.push({
          name: "High entropy token",
          category: "Possible secret",
          risk: "High",
          action: ACTION.BLOCK,
          preview: mask(token),
          index: text.indexOf(token)
        });
      }
    }

    let action = ACTION.ALLOW;
    let risk = "Low";
    for (const finding of findings) {
      if (finding.action === ACTION.BLOCK) action = ACTION.BLOCK;
      if (action !== ACTION.BLOCK && finding.action === ACTION.WARN) action = ACTION.WARN;
      if (RISK_WEIGHT[finding.risk] > RISK_WEIGHT[risk]) risk = finding.risk;
    }

    return {
      action,
      risk,
      findings,
      blocked: action === ACTION.BLOCK,
      warned: action === ACTION.WARN,
      message: buildMessage(action, findings)
    };
  }

  function buildMessage(action, findings) {
    if (!findings.length) return "No sensitive data detected.";
    const names = [...new Set(findings.map((finding) => finding.name))].slice(0, 3).join(", ");
    if (action === ACTION.BLOCK) return `Blocked: ${names}. Remove sensitive data before sending.`;
    return `Warning: ${names}. Review before sending.`;
  }

  function entropy(value) {
    const counts = {};
    for (const char of value) counts[char] = (counts[char] || 0) + 1;
    return Object.values(counts).reduce((sum, count) => {
      const p = count / value.length;
      return sum - p * Math.log2(p);
    }, 0);
  }

  function mask(value) {
    const text = String(value).trim();
    if (text.length <= 8) return "[REDACTED]";
    return `${text.slice(0, 3)}...[REDACTED]...${text.slice(-3)}`;
  }

  function likelyPaymentCard(value) {
    const digits = value.replace(/\D/g, "").split("").map(Number);
    if (digits.length < 13 || digits.length > 19) return false;
    let checksum = 0;
    const parity = digits.length % 2;
    digits.forEach((digit, index) => {
      let next = digit;
      if (index % 2 === parity) {
        next *= 2;
        if (next > 9) next -= 9;
      }
      checksum += next;
    });
    return checksum % 10 === 0;
  }

  window.AIGuardrailScanner = { inspectText };
})();
