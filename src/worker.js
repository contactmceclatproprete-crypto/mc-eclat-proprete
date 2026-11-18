
function normalize(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

function findColumn(columns, words) {
  return columns.find(name => {
    const n = normalize(name);
    return words.some(word => n.includes(word));
  });
}

function quote(name) {
  return '"' + name.replace(/"/g, '""') + '"';
}

async function verifySignature(rawBody, signature, secret) {
  if (!signature || !secret) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const digest = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(rawBody)
  );

  const expected = Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  const received = signature.replace(/^sha256=/i, "").trim().toLowerCase();

  return expected.length === received.length &&
    [...expected].every((char, i) => char === received[i]);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET") {
      return Response.json({
        service: "MC Éclat & Propreté - Cal.com",
        status: "online"
      });
    }

    if (request.method !== "POST" || url.pathname !== "/webhook") {
      return new Response("Not found", { status: 404 });
    }

    if (!env.DB) {
      return new Response("D1 binding DB missing", { status: 500 });
    }

    if (!env.CAL_WEBHOOK_SECRET) {
      return new Response("Webhook secret missing", { status: 500 });
    }

    const rawBody = await request.text();
    const signature = request.headers.get("X-Cal-Signature-256");

    const valid = await verifySignature(
      rawBody,
      signature,
      env.CAL_WEBHOOK_SECRET
    );

    if (!valid) {
      return new Response("Signature invalide", { status: 401 });
    }

    let body;

    try {
      body = JSON.parse(rawBody);
    } catch {
      return new Response("JSON invalide", { status: 400 });
    }

    const event = body.triggerEvent;
    const booking = body.payload || {};
    const attendee = booking.attendees?.[0] || {};

    if (!event) {
      return Response.json({ received: true });
    }

    if (![
      "BOOKING_CREATED",
      "BOOKING_RESCHEDULED",
      "BOOKING_CANCELLED"
    ].includes(event)) {
      return Response.json({ ignored: true, event });
    }

    const columnsResult = await env.DB
      .prepare("PRAGMA table_info(bookings)")
      .all();

    const columns = (columnsResult.results || []).map(row => row.name);

    if (!columns.length) {
      return new Response("Table bookings introuvable", { status: 500 });
    }

    const clientCol = findColumn(columns, ["nomduclient", "clientname", "name"]);
    const phoneCol = findColumn(columns, ["telephone", "phone"]);
    const emailCol = findColumn(columns, ["courriel", "email"]);
    const serviceCol = findColumn(columns, ["service"]);
    const dateCol = findColumn(columns, ["date"]);
    const timeCol = findColumn(columns, ["temps", "heure", "time"]);
    const addressCol = findColumn(columns, ["adresse", "address"]);
    const notesCol = findColumn(columns, ["notes", "remarques"]);
    const statusCol = findColumn(columns, ["statut", "status"]);

    if (!clientCol || !dateCol || !timeCol) {
      return new Response(
        "Colonnes client, date ou heure introuvables",
        { status: 500 }
      );
    }

    const start = booking.startTime || "";
    const client = attendee.name || booking.title || "Client Cal.com";
    const date = start.slice(0, 10);
    const time = start.slice(11, 16);

    if (!date || !time) {
      return new Response("Date ou heure absente", { status: 400 });
    }

    const values = new Map();

    values.set(clientCol, client);
    if (phoneCol) values.set(phoneCol, attendee.phone || "");
    if (emailCol) values.set(emailCol, attendee.email || "");
    if (serviceCol) values.set(serviceCol, booking.title || booking.type || "Nettoyage");
    values.set(dateCol, date);
    values.set(timeCol, time);
    if (addressCol) values.set(addressCol, booking.location || "");
    if (notesCol) values.set(notesCol, booking.description || "");
    if (statusCol) {
      values.set(
        statusCol,
        event === "BOOKING_CANCELLED" ? "annulé" : "confirmé"
      );
    }

    const existing = await env.DB.prepare(
      `SELECT rowid FROM bookings
       WHERE ${quote(clientCol)} = ?
       AND ${quote(dateCol)} = ?
       AND ${quote(timeCol)} = ?
       LIMIT 1`
    ).bind(client, date, time).first();

    if (existing) {
      if (event === "BOOKING_CANCELLED" && statusCol) {
        await env.DB.prepare(
          `UPDATE bookings SET ${quote(statusCol)} = ?
           WHERE rowid = ?`
        ).bind("annulé", existing.rowid).run();
      } else {
        const entries = [...values.entries()]
          .filter(([name]) => name !== clientCol &&
            name !== dateCol && name !== timeCol);

        if (entries.length) {
          const assignments = entries.map(([name]) =>
            `${quote(name)} = ?`
          ).join(", ");

          await env.DB.prepare(
            `UPDATE bookings SET ${assignments}
             WHERE rowid = ?`
          ).bind(...entries.map(([, value]) => value), existing.rowid).run();
        }
      }
    } else if (event !== "BOOKING_CANCELLED") {
      const entries = [...values.entries()];
      const names = entries.map(([name]) => quote(name)).join(", ");
      const placeholders = entries.map(() => "?").join(", ");

      await env.DB.prepare(
        `INSERT INTO bookings (${names}) VALUES (${placeholders})`
      ).bind(...entries.map(([, value]) => value)).run();
    }

    return Response.json({
      success: true,
      event,
      client,
      date,
      time
    });
  }
};
