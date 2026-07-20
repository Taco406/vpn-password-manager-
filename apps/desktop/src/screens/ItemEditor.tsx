import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  ArrowLeft,
  Eye,
  EyeOff,
  RefreshCw,
  Plus,
  X,
  Trash2,
  Globe,
  StickyNote,
  CreditCard,
  User,
  KeyRound,
  Loader2,
} from "lucide-react";
import type { ItemInput, ItemType } from "@sentinel/shared";
import { bridge } from "../bridge";
import { Button, Badge } from "../components/ui";

const typeMeta: { type: ItemType; label: string; icon: typeof Globe }[] = [
  { type: "login", label: "Login", icon: Globe },
  { type: "note", label: "Note", icon: StickyNote },
  { type: "card", label: "Card", icon: CreditCard },
  { type: "identity", label: "Identity", icon: User },
];

const inputCls =
  "w-full rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2.5 text-sm outline-none transition-colors placeholder:text-[var(--text-muted)] focus:border-[var(--accent)]/60";
const wrapCls =
  "flex items-center gap-2 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 transition-colors focus-within:border-[var(--accent)]/60";

const strengthLabels = ["Very weak", "Weak", "Fair", "Strong", "Excellent"] as const;

export function ItemEditor() {
  const { id } = useParams();
  const navigate = useNavigate();
  const isExisting = !!id;

  // --- form state (superset of all item types) ---
  const [type, setType] = useState<ItemType>("login");
  const [title, setTitle] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [pwTouched, setPwTouched] = useState(false); // true once the real value is in `password`
  const [showPassword, setShowPassword] = useState(false);
  const [pwScore, setPwScore] = useState<number | null>(null);
  const [urls, setUrls] = useState<string[]>([""]);
  const [notes, setNotes] = useState("");
  const [tags, setTags] = useState<string[]>([]);
  const [totpUri, setTotpUri] = useState("");
  const [hasTotp, setHasTotp] = useState(false);
  // card
  const [cardholder, setCardholder] = useState("");
  const [cardNumber, setCardNumber] = useState("");
  const [expMonth, setExpMonth] = useState("");
  const [expYear, setExpYear] = useState("");
  const [cvv, setCvv] = useState("");
  // identity
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");

  const [loading, setLoading] = useState(isExisting);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const titleRef = useRef<HTMLInputElement>(null);

  // Prefill when editing an existing item.
  useEffect(() => {
    if (!isExisting) {
      titleRef.current?.focus();
      return;
    }
    let cancelled = false;
    setLoading(true);
    bridge
      .vaultGet(id)
      .then((d) => {
        if (cancelled) return;
        setType(d.type);
        setTitle(d.title);
        setUsername(d.username ?? "");
        setUrls(d.urls.length ? d.urls.map((u) => u.url) : [""]);
        setNotes(d.notes ?? "");
        setTags(d.tags);
        setHasTotp(d.hasTotp);
        const cf = Object.fromEntries((d.customFields ?? []).map((f) => [f.name, f.value]));
        setCardholder(cf.cardholder ?? "");
        setCardNumber(cf.number ?? "");
        setExpMonth(cf.expMonth ?? (d.card?.expMonth != null ? String(d.card.expMonth) : ""));
        setExpYear(cf.expYear ?? (d.card?.expYear != null ? String(d.card.expYear) : ""));
        setCvv(cf.cvv ?? "");
        setFullName(cf.fullName ?? d.identity?.fullName ?? "");
        setEmail(cf.email ?? d.identity?.email ?? "");
        setPhone(cf.phone ?? d.identity?.phone ?? "");
        setLoading(false);
      })
      .catch(() => {
        if (cancelled) return;
        setError("Couldn't load this item.");
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [id, isExisting]);

  // Escape closes the confirm dialog, or leaves the editor.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      if (confirmOpen) setConfirmOpen(false);
      else goBack();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [confirmOpen]);

  function goBack() {
    if (isExisting) navigate(`/vault/${id}`);
    else navigate("/vault");
  }

  async function revealOrToggle() {
    if (pwTouched || !isExisting) {
      setShowPassword((s) => !s);
      return;
    }
    // Existing login, not yet loaded — pull the real value on demand.
    try {
      const pw = await bridge.vaultRevealField(id, "password");
      setPassword(pw);
      setPwTouched(true);
      setShowPassword(true);
    } catch {
      setError("Couldn't reveal the password.");
    }
  }

  async function generate() {
    try {
      const gen = await bridge.generatorPassword({
        length: 20,
        lower: true,
        upper: true,
        digits: true,
        symbols: true,
        excludeAmbiguous: true,
      });
      setPassword(gen.value);
      setPwScore(gen.score);
      setPwTouched(true);
      setShowPassword(true);
    } catch {
      setError("Couldn't generate a password.");
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim()) {
      setError("Give this item a title.");
      titleRef.current?.focus();
      return;
    }
    setError(null);
    setSaving(true);
    try {
      const input: ItemInput = { type, title: title.trim(), tags };
      if (isExisting) input.id = id;

      if (type === "login") {
        input.username = username.trim() || undefined;
        // Preserve the stored password when the user never touched it.
        const finalPw = pwTouched ? password : isExisting ? await bridge.vaultRevealField(id, "password") : password;
        input.password = finalPw || undefined;
        const cleanUrls = urls
          .map((u) => u.trim())
          .filter(Boolean)
          .map((url) => ({ url, mode: "domain" as const }));
        if (cleanUrls.length) input.urls = cleanUrls;
        if (totpUri.trim()) input.totpUri = totpUri.trim();
        if (notes.trim()) input.notes = notes.trim();
      } else if (type === "note") {
        if (notes.trim()) input.notes = notes.trim();
      } else if (type === "card") {
        input.customFields = [
          { name: "cardholder", value: cardholder.trim(), secret: false },
          { name: "number", value: cardNumber.trim(), secret: true },
          { name: "expMonth", value: expMonth.trim(), secret: false },
          { name: "expYear", value: expYear.trim(), secret: false },
          { name: "cvv", value: cvv.trim(), secret: true },
        ].filter((f) => f.value);
        if (notes.trim()) input.notes = notes.trim();
      } else if (type === "identity") {
        input.customFields = [
          { name: "fullName", value: fullName.trim(), secret: false },
          { name: "email", value: email.trim(), secret: false },
          { name: "phone", value: phone.trim(), secret: false },
        ].filter((f) => f.value);
        if (email.trim()) input.username = email.trim();
        if (notes.trim()) input.notes = notes.trim();
      }

      const savedId = await bridge.vaultSave(input);
      navigate(`/vault/${savedId}`);
    } catch {
      setError("Couldn't save. Please try again.");
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!isExisting) return;
    setDeleting(true);
    try {
      await bridge.vaultDelete(id);
      navigate("/vault");
    } catch {
      setError("Couldn't delete this item.");
      setDeleting(false);
      setConfirmOpen(false);
    }
  }

  // Passkeys are never created here, but an existing one can be opened to edit its
  // title/tags/notes; give it the right icon rather than falling back to the globe.
  const ActiveIcon = type === "passkey" ? KeyRound : (typeMeta.find((t) => t.type === type)?.icon ?? Globe);

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center text-[var(--text-muted)]">
        <Loader2 size={22} className="animate-spin" />
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="mx-auto max-w-2xl px-8 py-8"
    >
      <form onSubmit={handleSubmit}>
        {/* Header */}
        <div className="mb-6 flex items-center gap-3">
          <button
            type="button"
            onClick={goBack}
            aria-label="Back to vault"
            className="flex h-9 w-9 items-center justify-center rounded-[10px] border border-[var(--border-subtle)] text-[var(--text-secondary)] transition-colors hover:border-[var(--border-strong)] hover:text-[var(--text-primary)]"
          >
            <ArrowLeft size={18} />
          </button>
          <div className="flex flex-1 items-center gap-2">
            <ActiveIcon size={18} className="text-accent" />
            <h1 className="text-xl font-semibold">{isExisting ? "Edit item" : "New item"}</h1>
          </div>
        </div>

        {/* Type selector (new items only) */}
        {!isExisting && (
          <div className="mb-5 flex gap-2">
            {typeMeta.map(({ type: t, label, icon: Icon }) => (
              <button
                key={t}
                type="button"
                aria-pressed={type === t}
                onClick={() => setType(t)}
                className={`flex flex-1 items-center justify-center gap-2 rounded-[10px] border py-2.5 text-sm transition-colors ${
                  type === t
                    ? "border-[var(--accent)]/50 bg-[var(--accent)]/10 text-[var(--accent)]"
                    : "border-[var(--border-subtle)] text-[var(--text-secondary)] hover:border-[var(--border-strong)]"
                }`}
              >
                <Icon size={15} /> {label}
              </button>
            ))}
          </div>
        )}

        <div className="surface flex flex-col gap-5 p-5">
          <Field id="title" label="Title">
            <input
              id="title"
              ref={titleRef}
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. GitHub"
              className={inputCls}
              autoComplete="off"
            />
          </Field>

          {type === "login" && (
            <>
              <Field id="username" label="Username">
                <input
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="you@example.com"
                  className={inputCls}
                  autoComplete="off"
                />
              </Field>

              <Field
                id="password"
                label="Password"
                hint={
                  isExisting && !pwTouched
                    ? "The stored password is kept unless you reveal or type a new one."
                    : undefined
                }
              >
                <div className={wrapCls}>
                  <input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      setPwTouched(true);
                      setPwScore(null);
                    }}
                    placeholder={isExisting && !pwTouched ? "••••••••••••" : "Enter or generate a password"}
                    className="mono flex-1 bg-transparent py-2.5 text-sm outline-none placeholder:text-[var(--text-muted)] placeholder:font-sans"
                    autoComplete="new-password"
                  />
                  <button
                    type="button"
                    onClick={revealOrToggle}
                    aria-label={showPassword ? "Hide password" : "Reveal password"}
                    className="text-[var(--text-muted)] transition-colors hover:text-[var(--text-primary)]"
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                  <button
                    type="button"
                    onClick={generate}
                    aria-label="Generate password"
                    className="flex items-center gap-1.5 rounded-[8px] px-2 py-1 text-xs text-[var(--text-secondary)] transition-colors hover:text-[var(--accent)]"
                  >
                    <RefreshCw size={14} /> Generate
                  </button>
                </div>
                {pwScore != null && (
                  <div className="mt-2">
                    <Badge tone={pwScore >= 3 ? "ok" : pwScore >= 2 ? "warn" : "danger"}>
                      {strengthLabels[pwScore]}
                    </Badge>
                  </div>
                )}
              </Field>

              <Field id="urls" label="Websites">
                <div className="flex flex-col gap-2">
                  {urls.map((u, i) => (
                    <div key={i} className={wrapCls}>
                      <input
                        value={u}
                        onChange={(e) => setUrls(urls.map((x, j) => (j === i ? e.target.value : x)))}
                        placeholder="https://example.com"
                        className="flex-1 bg-transparent py-2.5 text-sm outline-none placeholder:text-[var(--text-muted)]"
                        autoComplete="off"
                        aria-label={`Website ${i + 1}`}
                      />
                      {urls.length > 1 && (
                        <button
                          type="button"
                          onClick={() => setUrls(urls.filter((_, j) => j !== i))}
                          aria-label={`Remove website ${i + 1}`}
                          className="text-[var(--text-muted)] transition-colors hover:text-[var(--danger)]"
                        >
                          <X size={15} />
                        </button>
                      )}
                    </div>
                  ))}
                  <button
                    type="button"
                    onClick={() => setUrls([...urls, ""])}
                    className="flex w-fit items-center gap-1.5 text-xs text-[var(--text-secondary)] transition-colors hover:text-[var(--accent)]"
                  >
                    <Plus size={14} /> Add website
                  </button>
                </div>
              </Field>

              <Field
                id="totp"
                label="One-time code (TOTP)"
                hint={
                  hasTotp
                    ? "A one-time code is already configured. Enter a new otpauth:// URI to replace it."
                    : "Optional. Paste an otpauth:// URI."
                }
              >
                <input
                  id="totp"
                  value={totpUri}
                  onChange={(e) => setTotpUri(e.target.value)}
                  placeholder="otpauth://totp/..."
                  className={`${inputCls} mono`}
                  autoComplete="off"
                />
              </Field>
            </>
          )}

          {type === "card" && (
            <>
              <Field id="cardholder" label="Cardholder">
                <input
                  id="cardholder"
                  value={cardholder}
                  onChange={(e) => setCardholder(e.target.value)}
                  placeholder="Name on card"
                  className={inputCls}
                  autoComplete="off"
                />
              </Field>
              <Field id="number" label="Card number">
                <input
                  id="number"
                  value={cardNumber}
                  onChange={(e) => setCardNumber(e.target.value)}
                  placeholder="0000 0000 0000 0000"
                  inputMode="numeric"
                  className={`${inputCls} mono`}
                  autoComplete="off"
                />
              </Field>
              <div className="grid grid-cols-3 gap-3">
                <Field id="expMonth" label="Exp. month">
                  <input
                    id="expMonth"
                    value={expMonth}
                    onChange={(e) => setExpMonth(e.target.value.replace(/\D/g, "").slice(0, 2))}
                    placeholder="MM"
                    inputMode="numeric"
                    className={`${inputCls} mono`}
                    autoComplete="off"
                  />
                </Field>
                <Field id="expYear" label="Exp. year">
                  <input
                    id="expYear"
                    value={expYear}
                    onChange={(e) => setExpYear(e.target.value.replace(/\D/g, "").slice(0, 4))}
                    placeholder="YYYY"
                    inputMode="numeric"
                    className={`${inputCls} mono`}
                    autoComplete="off"
                  />
                </Field>
                <Field id="cvv" label="CVV">
                  <input
                    id="cvv"
                    type="password"
                    value={cvv}
                    onChange={(e) => setCvv(e.target.value.replace(/\D/g, "").slice(0, 4))}
                    placeholder="•••"
                    inputMode="numeric"
                    className={`${inputCls} mono`}
                    autoComplete="off"
                  />
                </Field>
              </div>
            </>
          )}

          {type === "identity" && (
            <>
              <Field id="fullName" label="Full name">
                <input
                  id="fullName"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Jane Doe"
                  className={inputCls}
                  autoComplete="off"
                />
              </Field>
              <Field id="email" label="Email">
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="jane@example.com"
                  className={inputCls}
                  autoComplete="off"
                />
              </Field>
              <Field id="phone" label="Phone">
                <input
                  id="phone"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  placeholder="+1 555 010 0000"
                  inputMode="tel"
                  className={inputCls}
                  autoComplete="off"
                />
              </Field>
            </>
          )}

          {/* Notes for every type */}
          <Field id="notes" label={type === "note" ? "Note" : "Notes"}>
            <textarea
              id="notes"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={type === "note" ? 8 : 3}
              placeholder={type === "note" ? "Write your secure note…" : "Additional notes"}
              className={`${inputCls} resize-y`}
            />
          </Field>

          <Field id="tags" label="Tags">
            <TagInput tags={tags} setTags={setTags} />
          </Field>
        </div>

        {error && (
          <div className="mt-4 rounded-[10px] border border-[var(--danger)]/30 bg-[var(--danger)]/10 px-3 py-2 text-sm text-[var(--danger)]">
            {error}
          </div>
        )}

        {/* Footer actions */}
        <div className="mt-6 flex items-center gap-3">
          {isExisting && (
            <Button variant="danger" onClick={() => setConfirmOpen(true)} className="!px-3">
              <Trash2 size={15} /> Delete
            </Button>
          )}
          <div className="ml-auto flex items-center gap-2">
            <Button variant="ghost" onClick={goBack}>
              Cancel
            </Button>
            <Button type="submit">
              {saving ? (
                <>
                  <Loader2 size={15} className="animate-spin" /> Saving…
                </>
              ) : isExisting ? (
                "Save changes"
              ) : (
                "Create item"
              )}
            </Button>
          </div>
        </div>
      </form>

      {/* Delete confirmation */}
      <AnimatePresence>
        {confirmOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-8"
            onClick={() => setConfirmOpen(false)}
          >
            <motion.div
              role="dialog"
              aria-modal="true"
              aria-labelledby="delete-title"
              initial={{ opacity: 0, scale: 0.96, y: 8 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.96, y: 8 }}
              onClick={(e) => e.stopPropagation()}
              className="surface-overlay w-[380px] p-5"
            >
              <h2 id="delete-title" className="text-base font-semibold">
                Delete item?
              </h2>
              <p className="mt-2 text-sm text-[var(--text-secondary)]">
                <span className="text-[var(--text-primary)]">{title || "This item"}</span> will be permanently removed
                from your vault. This can&apos;t be undone.
              </p>
              <div className="mt-5 flex justify-end gap-2">
                <Button variant="ghost" onClick={() => setConfirmOpen(false)}>
                  Cancel
                </Button>
                <Button variant="danger" onClick={handleDelete}>
                  {deleting ? (
                    <>
                      <Loader2 size={15} className="animate-spin" /> Deleting…
                    </>
                  ) : (
                    "Delete"
                  )}
                </Button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

function Field({
  id,
  label,
  hint,
  children,
}: {
  id: string;
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label htmlFor={id} className="mb-1.5 block text-xs uppercase tracking-wide text-[var(--text-muted)]">
        {label}
      </label>
      {children}
      {hint && <p className="mt-1.5 text-xs text-[var(--text-muted)]">{hint}</p>}
    </div>
  );
}

function TagInput({ tags, setTags }: { tags: string[]; setTags: (t: string[]) => void }) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const t = draft.trim().replace(/,$/, "");
    if (t && !tags.includes(t)) setTags([...tags, t]);
    setDraft("");
  };
  return (
    <div className="flex flex-wrap items-center gap-1.5 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-2.5 py-2 transition-colors focus-within:border-[var(--accent)]/60">
      {tags.map((t) => (
        <span
          key={t}
          className="inline-flex items-center gap-1 rounded-full border border-[var(--accent)]/30 bg-[var(--accent)]/12 px-2 py-0.5 text-xs font-medium text-[var(--accent)]"
        >
          {t}
          <button type="button" aria-label={`Remove tag ${t}`} onClick={() => setTags(tags.filter((x) => x !== t))}>
            <X size={11} />
          </button>
        </span>
      ))}
      <input
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            add();
          } else if (e.key === "Backspace" && !draft && tags.length) {
            setTags(tags.slice(0, -1));
          }
        }}
        onBlur={add}
        placeholder={tags.length ? "" : "Add tags…"}
        className="min-w-[80px] flex-1 bg-transparent py-0.5 text-sm outline-none placeholder:text-[var(--text-muted)]"
        aria-label="Add tag"
      />
    </div>
  );
}
