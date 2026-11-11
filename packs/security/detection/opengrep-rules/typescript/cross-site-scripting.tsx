import DOMPurify from "dompurify";
import ReactMarkdown from "react-markdown";
import rehypeRaw from "rehype-raw";
import rehypeSanitize from "rehype-sanitize";
import $ from "jquery";

export const Entry = ({ response }: { response: string }) => (
  // ruleid: traust-ts-xss-dangerously-set-inner-html
  <div dangerouslySetInnerHTML={{ __html: interpolateLink(response) }} />
);

export const Clean = ({ response }: { response: string }) => (
  // ok: traust-ts-xss-dangerously-set-inner-html
  <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(response) }} />
);

// ok: traust-ts-xss-dangerously-set-inner-html
export const Fixed = () => <div dangerouslySetInnerHTML={{ __html: "<b>static</b>" }} />;

export const Help = ({ t, i18nDescription, sanitizedContent }: any) => (
  <>
    {/* ok: traust-ts-xss-dangerously-set-inner-html */}
    <p dangerouslySetInnerHTML={{ __html: t("shared:techPreviewPopoverHtml") }} />
    {/* ok: traust-ts-xss-dangerously-set-inner-html */}
    <p dangerouslySetInnerHTML={{ __html: i18nDescription }} />
    {/* ok: traust-ts-xss-dangerously-set-inner-html */}
    <p dangerouslySetInnerHTML={{ __html: sanitizedContent ?? "" }} />
  </>
);

export const Warning = ({ t, resources }: any) => (
  // ruleid: traust-ts-xss-dangerously-set-inner-html
  <p dangerouslySetInnerHTML={{ __html: `${t("Warning:")} ${resources.join(", ")}` }} />
);

export function openRawTab(logs: string): void {
  const rawWindow = window.open("about:blank");
  // ruleid: traust-ts-xss-dom-html-sink
  rawWindow?.document.write(`<pre>${logs}</pre>`);
  // ok: traust-ts-xss-dom-html-sink
  document.write("<p>loading</p>");
}

export async function loadConfig(response: Response): Promise<void> {
  const script = await response.text();
  const configScript = document.createElement("script");
  // ruleid: traust-ts-xss-dom-html-sink
  configScript.innerHTML = script;
  const box = document.getElementById("box")!;
  // ok: traust-ts-xss-dom-html-sink
  box.innerHTML = "";
  // ok: traust-ts-xss-dom-html-sink
  box.innerHTML = DOMPurify.sanitize(script);
  // ruleid: traust-ts-xss-dom-html-sink
  box.insertAdjacentHTML("beforeend", script);
  // ruleid: traust-ts-xss-dom-html-sink
  $("#answers").html(marked.parse(script));
  // ok: traust-ts-xss-dom-html-sink
  box.textContent = script;
}

export const Docs = ({ text }: { text: string }) => (
  // ruleid: traust-ts-xss-markdown-raw-html
  <ReactMarkdown rehypePlugins={[rehypeRaw]}>{text}</ReactMarkdown>
);

export const SafeDocs = ({ text }: { text: string }) => (
  // ok: traust-ts-xss-markdown-raw-html
  <ReactMarkdown rehypePlugins={[rehypeRaw, rehypeSanitize]}>{text}</ReactMarkdown>
);

export function bundle(req: any, res: any): void {
  const sha = req.params.sha;
  // ruleid: traust-ts-xss-reflected-response-taint
  res.status(404).send(`Bundle ${sha} not found`);
  // ruleid: traust-ts-xss-reflected-response-taint
  res.send("unknown filetype " + req.query.filetype);
  // ok: traust-ts-xss-reflected-response-taint
  res.status(404).send(`Bundle ${escapeHtml(sha)} not found`);
  // ok: traust-ts-xss-reflected-response-taint
  res.json({ error: `Bundle ${sha} not found` });
}

export function viewer(req: any, res: any): void {
  const { namespace } = req.query;
  // ruleid: traust-ts-xss-reflected-response-taint
  res.status(403).send(`User is not allowed in namespace ${namespace}`);
  // ruleid: traust-ts-xss-reflected-response-taint
  res.send(JSON.stringify({ echo: req.body.spec }));
}
