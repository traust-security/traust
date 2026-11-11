import cors from "cors";
import express from "express";

const app = express();
// ruleid: traust-ts-cors-any-origin-with-credentials
app.use(cors({ origin: true, credentials: true }));
// ruleid: traust-ts-cors-any-origin-with-credentials
app.use(cors({ credentials: true, origin: (origin, callback) => callback(null, true) }));
// ok: traust-ts-cors-any-origin-with-credentials
app.use(cors({ origin: ["https://app.example.org"], credentials: true }));
// ok: traust-ts-cors-any-origin-with-credentials
app.use(cors({ origin: true }));

export function bootstrap(nest: { enableCors(o: object): void }) {
  // ruleid: traust-ts-cors-any-origin-with-credentials
  nest.enableCors({ origin: /.*/, credentials: true, methods: "GET,POST" });
}

app.use((req, res, next) => {
  // ruleid: traust-ts-cors-any-origin-with-credentials
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});
