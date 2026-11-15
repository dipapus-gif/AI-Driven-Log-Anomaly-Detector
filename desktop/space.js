/* Animated space backdrop: stars, nebula glow, a ringed planet, a moon, shooting stars and a
   small rocket. No dependencies. Used by the sign-in screen (mode "hero") and injected behind
   the dashboard (mode "ambient": calmer, no planet or rocket).

   Usage:  SpaceBackdrop.mount(canvasElement, { mode: "hero" | "ambient" })
   Honors prefers-reduced-motion (draws one still frame) and pauses while the window is hidden. */
(function (root) {
  "use strict";

  var TAU = Math.PI * 2;
  var BASE = "#05030d";
  // [rgb, probability]: mostly white, with a few lavender, cyan, gold and pink stars.
  var STAR_COLORS = [["255,255,255", 0.70], ["196,181,253", 0.12], ["103,232,249", 0.08], ["253,224,71", 0.06], ["249,168,212", 0.04]];

  function rand(a, b) { return a + Math.random() * (b - a); }
  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
  function pickColor() {
    var r = Math.random(), acc = 0;
    for (var i = 0; i < STAR_COLORS.length; i++) { acc += STAR_COLORS[i][1]; if (r < acc) return STAR_COLORS[i][0]; }
    return STAR_COLORS[0][0];
  }

  function mount(canvas, options) {
    var hero = !options || options.mode !== "ambient";
    var ctx = canvas.getContext("2d");
    var mq = root.matchMedia ? root.matchMedia("(prefers-reduced-motion: reduce)") : null;
    var still = !!(mq && mq.matches);
    var W = 0, H = 0, dpr = 1;
    var stars = [], shooters = [], nebula = null;
    var time = 0, last = 0, raf = 0, running = false;
    var nextShooter = hero ? 3 : 7;
    var nextRocket = hero ? 5 : Infinity;
    var rocket = null;

    function buildNebula() {
      var w = Math.max(2, Math.round(W / 2)), h = Math.max(2, Math.round(H / 2));
      nebula = document.createElement("canvas");
      nebula.width = w; nebula.height = h;
      var n = nebula.getContext("2d");
      var k = hero ? 1 : 0.62;
      var blobs = [
        { x: 0.14, y: 0.26, r: 0.55, c: "124,58,237", a: 0.36 },
        { x: 0.86, y: 0.16, r: 0.50, c: "217,70,239", a: 0.22 },
        { x: 0.56, y: 0.92, r: 0.62, c: "59,130,246", a: 0.20 },
        { x: 0.08, y: 0.96, r: 0.42, c: "34,211,238", a: 0.13 },
        { x: 0.52, y: 0.46, r: 0.52, c: "91,33,182", a: 0.20 }
      ];
      n.fillStyle = BASE;
      n.fillRect(0, 0, w, h);
      n.globalCompositeOperation = "lighter";
      for (var i = 0; i < blobs.length; i++) {
        var b = blobs[i], rad = b.r * Math.max(w, h);
        var g = n.createRadialGradient(b.x * w, b.y * h, 0, b.x * w, b.y * h, rad);
        g.addColorStop(0, "rgba(" + b.c + "," + (b.a * k).toFixed(3) + ")");
        g.addColorStop(0.5, "rgba(" + b.c + "," + (b.a * k * 0.35).toFixed(3) + ")");
        g.addColorStop(1, "rgba(" + b.c + ",0)");
        n.fillStyle = g;
        n.fillRect(0, 0, w, h);
      }
    }

    function buildStars() {
      var count = clamp(Math.round((W * H) / (hero ? 2800 : 4200)), 90, 420);
      stars = [];
      for (var i = 0; i < count; i++) {
        var z = Math.pow(Math.random(), 1.6); // most stars are far away and small
        stars.push({
          x: Math.random(), y: Math.random(), z: z,
          size: 0.5 + z * 1.5, color: pickColor(),
          speed: 0.0015 + z * 0.006,            // fraction of the width per second
          phase: rand(0, TAU), rate: rand(0.6, 2.2),
          base: 0.35 + z * 0.55
        });
      }
    }

    function resize() {
      var cw = canvas.clientWidth, ch = canvas.clientHeight;
      if (!cw || !ch) return;
      dpr = Math.min(root.devicePixelRatio || 1, hero ? 2 : 1.5);
      W = cw; H = ch;
      canvas.width = Math.round(W * dpr);
      canvas.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      buildNebula();
      buildStars();
      if (!running) draw();
    }

    // ---- drawing helpers ----------------------------------------------------

    function ring(cx, cy, r, tilt, front) {
      var a0 = front ? 0 : Math.PI, a1 = front ? Math.PI : TAU;
      var bands = [
        { s: 1.00, w: 0.11, c: "196,181,253", a: 0.38 },
        { s: 1.14, w: 0.05, c: "244,114,182", a: 0.55 },
        { s: 1.28, w: 0.03, c: "103,232,249", a: 0.34 }
      ];
      for (var i = 0; i < bands.length; i++) {
        var b = bands[i];
        ctx.beginPath();
        ctx.ellipse(cx, cy, r * 1.75 * b.s, r * 0.42 * b.s, tilt, a0, a1);
        ctx.strokeStyle = "rgba(" + b.c + "," + b.a + ")";
        ctx.lineWidth = Math.max(1, r * b.w);
        ctx.stroke();
      }
    }

    function drawPlanet(cx, cy, r) {
      var glow = ctx.createRadialGradient(cx, cy, r * 0.9, cx, cy, r * 1.4);
      glow.addColorStop(0, "rgba(167,139,250,0.34)");
      glow.addColorStop(1, "rgba(167,139,250,0)");
      ctx.fillStyle = glow;
      ctx.beginPath(); ctx.arc(cx, cy, r * 1.4, 0, TAU); ctx.fill();

      var tilt = -0.32;
      ring(cx, cy, r, tilt, false);

      ctx.save();
      ctx.beginPath(); ctx.arc(cx, cy, r, 0, TAU); ctx.clip();
      var body = ctx.createRadialGradient(cx - r * 0.4, cy - r * 0.45, r * 0.08, cx, cy, r * 1.05);
      body.addColorStop(0, "#f3e8ff");
      body.addColorStop(0.22, "#b79cff");
      body.addColorStop(0.6, "#6d28d9");
      body.addColorStop(1, "#1a0838");
      ctx.fillStyle = body;
      ctx.fillRect(cx - r, cy - r, r * 2, r * 2);
      ctx.translate(cx, cy); ctx.rotate(tilt);
      var stripes = ["#ec4899", "#22d3ee", "#fbbf24", "#ec4899"];
      for (var i = 0; i < stripes.length; i++) {
        ctx.globalAlpha = 0.16;
        ctx.fillStyle = stripes[i];
        ctx.fillRect(-r, -r * 0.62 + i * r * 0.34, r * 2, r * 0.09);
      }
      ctx.globalAlpha = 1;
      ctx.rotate(-tilt); ctx.translate(-cx, -cy);
      var shade = ctx.createRadialGradient(cx - r * 0.55, cy - r * 0.55, r * 0.2, cx + r * 0.2, cy + r * 0.2, r * 1.4);
      shade.addColorStop(0, "rgba(5,3,13,0)");
      shade.addColorStop(0.55, "rgba(5,3,13,0.18)");
      shade.addColorStop(1, "rgba(5,3,13,0.88)");
      ctx.fillStyle = shade;
      ctx.fillRect(cx - r, cy - r, r * 2, r * 2);
      ctx.restore();

      ring(cx, cy, r, tilt, true);
    }

    function drawMoon(cx, cy, r) {
      var g = ctx.createRadialGradient(cx - r * 0.4, cy - r * 0.4, r * 0.1, cx, cy, r);
      g.addColorStop(0, "#f0fdfa"); g.addColorStop(0.4, "#5eead4"); g.addColorStop(1, "#0b2a30");
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(cx, cy, r, 0, TAU); ctx.fill();
      var s = ctx.createRadialGradient(cx - r * 0.6, cy - r * 0.6, r * 0.3, cx + r * 0.3, cy + r * 0.3, r * 1.3);
      s.addColorStop(0, "rgba(5,3,13,0)"); s.addColorStop(1, "rgba(5,3,13,0.85)");
      ctx.fillStyle = s;
      ctx.beginPath(); ctx.arc(cx, cy, r, 0, TAU); ctx.fill();
    }

    function drawRocket(x, y, angle, t) {
      ctx.save();
      ctx.translate(x, y); ctx.rotate(angle);
      var flick = 0.8 + 0.2 * Math.sin(t * 38) + 0.08 * Math.sin(t * 91);
      var fl = 30 * flick;
      var f = ctx.createLinearGradient(-12, 0, -12 - fl, 0);
      f.addColorStop(0, "rgba(253,224,71,0.95)"); f.addColorStop(0.5, "rgba(244,114,182,0.7)"); f.addColorStop(1, "rgba(124,58,237,0)");
      ctx.fillStyle = f;
      ctx.beginPath(); ctx.moveTo(-12, -5); ctx.quadraticCurveTo(-12 - fl, 0, -12, 5); ctx.closePath(); ctx.fill();
      ctx.fillStyle = "#8b5cf6";
      ctx.beginPath(); ctx.moveTo(-8, -8); ctx.lineTo(-19, -17); ctx.lineTo(-2, -8); ctx.closePath(); ctx.fill();
      ctx.beginPath(); ctx.moveTo(-8, 8); ctx.lineTo(-19, 17); ctx.lineTo(-2, 8); ctx.closePath(); ctx.fill();
      var body = ctx.createLinearGradient(0, -8, 0, 8);
      body.addColorStop(0, "#faf5ff"); body.addColorStop(1, "#b79cff");
      ctx.fillStyle = body;
      ctx.beginPath();
      ctx.moveTo(-14, -8); ctx.lineTo(14, -8); ctx.quadraticCurveTo(30, -6, 35, 0);
      ctx.quadraticCurveTo(30, 6, 14, 8); ctx.lineTo(-14, 8); ctx.quadraticCurveTo(-19, 0, -14, -8);
      ctx.closePath(); ctx.fill();
      ctx.fillStyle = "rgba(236,72,153,0.85)";
      ctx.fillRect(-4, -8, 4, 16);
      ctx.fillStyle = "#22d3ee";
      ctx.beginPath(); ctx.arc(14, 0, 4, 0, TAU); ctx.fill();
      ctx.strokeStyle = "#1e1b4b"; ctx.lineWidth = 1.2; ctx.stroke();
      ctx.restore();
    }

    // ---- update and draw ------------------------------------------------------

    function spawnShooter() {
      var ang = rand(0.35, 0.6);
      shooters.push({
        x: rand(0.15, 1.05) * W, y: rand(-0.05, 0.4) * H,
        vx: Math.cos(ang) * -1, vy: Math.sin(ang),   // heads down and to the left
        len: rand(110, 220), speed: rand(700, 1000), life: 0, max: rand(0.7, 1.1)
      });
    }

    function update(dt) {
      time += dt;
      for (var i = 0; i < stars.length; i++) {
        var s = stars[i];
        s.x -= s.speed * dt;
        if (s.x < -0.01) { s.x += 1.02; s.y = Math.random(); }
      }
      nextShooter -= dt;
      if (nextShooter <= 0) { spawnShooter(); nextShooter = hero ? rand(5, 10) : rand(9, 18); }
      for (var j = shooters.length - 1; j >= 0; j--) {
        var m = shooters[j];
        m.life += dt;
        m.x += m.vx * m.speed * dt; m.y += m.vy * m.speed * dt;
        if (m.life > m.max) shooters.splice(j, 1);
      }
      nextRocket -= dt;
      if (!rocket && nextRocket <= 0) { rocket = { u: 0, dur: rand(20, 26), seed: rand(0, 10) }; }
      if (rocket) {
        rocket.u += dt / rocket.dur;
        if (rocket.u >= 1) { rocket = null; nextRocket = rand(28, 45); }
      }
    }

    function rocketPose(u) {
      function pos(p) {
        return { x: -90 + (W + 180) * p, y: H * (0.8 - 0.52 * p) + Math.sin(p * 7 + 1) * 14 };
      }
      var a = pos(u), b = pos(Math.min(1, u + 0.01));
      return { x: a.x, y: a.y, angle: Math.atan2(b.y - a.y, b.x - a.x) };
    }

    function draw() {
      if (!W || !H) return;
      ctx.globalAlpha = 1;
      ctx.fillStyle = BASE;
      ctx.fillRect(0, 0, W, H);

      var ox = Math.sin(time * 0.05) * W * 0.012, oy = Math.cos(time * 0.04) * H * 0.012;
      ctx.globalAlpha = 0.92 + 0.08 * Math.sin(time * 0.3);
      ctx.drawImage(nebula, -W * 0.02 + ox, -H * 0.02 + oy, W * 1.04, H * 1.04);
      ctx.globalAlpha = 1;

      for (var i = 0; i < stars.length; i++) {
        var s = stars[i];
        var tw = 0.65 + 0.35 * Math.sin(time * s.rate + s.phase);
        var a = s.base * tw * (hero ? 1 : 0.8);
        var x = s.x * W, y = s.y * H;
        ctx.fillStyle = "rgba(" + s.color + "," + a.toFixed(2) + ")";
        ctx.beginPath(); ctx.arc(x, y, s.size * 0.62, 0, TAU); ctx.fill();
        if (s.size > 1.5) {
          ctx.fillStyle = "rgba(" + s.color + "," + (a * 0.16).toFixed(3) + ")";
          ctx.beginPath(); ctx.arc(x, y, s.size * 2.6, 0, TAU); ctx.fill();
        }
      }

      if (hero) {
        var minSide = Math.min(W, H);
        var pr = clamp(minSide * 0.27, 90, 270);
        drawPlanet(W * 0.86, H * 1.0 + Math.sin(time * 0.2) * 3, pr);
        var mr = clamp(minSide * 0.034, 13, 32);
        drawMoon(W * 0.12 + Math.sin(time * 0.07) * 22, H * 0.2 + Math.cos(time * 0.09) * 10, mr);
      }

      for (var j = 0; j < shooters.length; j++) {
        var m = shooters[j];
        var k = m.life / m.max, fade = Math.sin(Math.min(1, k) * Math.PI);
        var tx = m.x - m.vx * m.len, ty = m.y - m.vy * m.len;
        var g = ctx.createLinearGradient(m.x, m.y, tx, ty);
        g.addColorStop(0, "rgba(255,255,255," + (0.95 * fade).toFixed(2) + ")");
        g.addColorStop(0.3, "rgba(196,181,253," + (0.5 * fade).toFixed(2) + ")");
        g.addColorStop(1, "rgba(124,58,237,0)");
        ctx.strokeStyle = g; ctx.lineWidth = 1.8; ctx.lineCap = "round";
        ctx.beginPath(); ctx.moveTo(m.x, m.y); ctx.lineTo(tx, ty); ctx.stroke();
      }

      if (rocket) {
        var p = rocketPose(rocket.u);
        for (var t = 1; t <= 10; t++) {  // faint exhaust trail
          var q = rocketPose(Math.max(0, rocket.u - t * 0.004));
          ctx.fillStyle = "rgba(244,114,182," + (0.22 - t * 0.02).toFixed(3) + ")";
          ctx.beginPath(); ctx.arc(q.x - 14 * Math.cos(q.angle), q.y - 14 * Math.sin(q.angle), 4.5 - t * 0.3, 0, TAU); ctx.fill();
        }
        drawRocket(p.x, p.y, p.angle, time);
      }
    }

    // ---- loop -------------------------------------------------------------------

    function frame(ts) {
      if (!running) return;
      var dt = Math.min(0.05, ((ts - last) / 1000) || 0);
      last = ts;
      update(dt);
      draw();
      raf = root.requestAnimationFrame(frame);
    }
    function start() {
      if (running) return;
      if (still) { draw(); return; }
      running = true; last = performance.now();
      raf = root.requestAnimationFrame(frame);
    }
    function stop() { running = false; if (raf) root.cancelAnimationFrame(raf); raf = 0; }

    document.addEventListener("visibilitychange", function () { if (document.hidden) stop(); else start(); });
    if (root.ResizeObserver) new root.ResizeObserver(resize).observe(canvas); else root.addEventListener("resize", resize);
    if (mq && mq.addEventListener) mq.addEventListener("change", function (e) { still = e.matches; if (still) { stop(); draw(); } else start(); });

    time = still ? 6 : 0;   // a still frame shows the scene already in progress
    resize();
    start();
    return { start: start, stop: stop, redraw: draw };
  }

  root.SpaceBackdrop = { mount: mount };
})(typeof window !== "undefined" ? window : this);
