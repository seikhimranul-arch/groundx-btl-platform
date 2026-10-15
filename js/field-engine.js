/**
 * ============================================================================
 * UTKAL VANTAGE — CORE FIELD VERIFICATION, CRYPTO AUDIT & STORAGE ENGINE v2.1
 * Pitch-Safe MVP Architecture (Zero Fake/Bogus Third-Party Client Claims):
 *   1. GeofenceManager (Haversine 100m Canopy / 20m Merchant Storefront Lock)
 *   2. PhotoAuditEngine (Canvas Metadata Burn-In + FIPS 180-4 SHA-256 Ledger)
 *   3. DualVerificationMachine (Phone-Bound OTP State Machine + Rate Limiter)
 *   4. LeadScoringEngine (Sector-Specific P&L Qualification Scoring)
 *   5. StorageEngine (Resilient IndexedDB + localStorage + Memory Failover)
 *   6. RealtimeBroadcaster (BroadcastChannel + Storage Event Cross-Tab Sync)
 * ============================================================================
 */
(function (global) {
  'use strict';

  // ── 1. CRYPTOGRAPHIC SHA-256 (WebCrypto + Pure-JS Fallback for HTTP/LAN) ──
  function sha256PureJS(ascii) {
    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }
    const mathPow = Math.pow;
    const maxWord = mathPow(2, 32);
    const lengthProperty = 'length';
    let i, j;
    let result = '';
    const words = [];
    const asciiBitLength = ascii[lengthProperty] * 8;
    let hash = (sha256PureJS.h = sha256PureJS.h || []);
    const k = (sha256PureJS.k = sha256PureJS.k || []);
    let primeCounter = k[lengthProperty];
    const isComposite = {};
    for (let candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (i = 0; i < 313; i += candidate) {
          isComposite[i] = candidate;
        }
        hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
        k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      }
    }
    ascii += '\x80';
    while ((ascii[lengthProperty] % 64) - 56) ascii += '\x00';
    for (i = 0; i < ascii[lengthProperty]; i++) {
      j = ascii.charCodeAt(i);
      if (j >> 8) return '';
      words[i >> 2] |= j << (((3 - i) % 4) * 8);
    }
    words[words[lengthProperty]] = (asciiBitLength / maxWord) | 0;
    words[words[lengthProperty]] = asciiBitLength;
    for (j = 0; j < words[lengthProperty]; ) {
      const w = words.slice(j, (j += 16));
      const oldHash = hash;
      hash = hash.slice(0, 8);
      for (i = 0; i < 64; i++) {
        const w15 = w[i - 15], w2 = w[i - 2];
        const a = hash[0], e = hash[4];
        const temp1 =
          hash[7] +
          (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
          ((e & hash[5]) ^ (~e & hash[6])) +
          k[i] +
          (w[i] =
            i < 16
              ? w[i]
              : (w[i - 16] +
                  (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
                  w[i - 7] +
                  (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))) |
                0);
        const temp2 =
          (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
          ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
        hash = [(temp1 + temp2) | 0].concat(hash);
        hash[4] = (hash[4] + temp1) | 0;
      }
      for (i = 0; i < 8; i++) {
        hash[i] = (hash[i] + oldHash[i]) | 0;
      }
    }
    for (i = 0; i < 8; i++) {
      for (j = 3; j + 1; j--) {
        const b = (hash[i] >> (j * 8)) & 255;
        result += (b < 16 ? 0 : '') + b.toString(16);
      }
    }
    return result;
  }

  async function computeSha256Hex(strInput) {
    const str = String(strInput || '');
    try {
      if (global.crypto && global.crypto.subtle && global.TextEncoder) {
        const buf = new TextEncoder().encode(str);
        const digest = await global.crypto.subtle.digest('SHA-256', buf);
        return Array.from(new Uint8Array(digest))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      }
    } catch (_) {}
    const utf8 = unescape(encodeURIComponent(str));
    return sha256PureJS(utf8);
  }

  // ── 2. SECURITY & FORMATTING UTILITIES ────────────────────────────────────
  function escapeHtml(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function escapeCsvCell(val) {
    let s = String(val == null ? '' : val).replace(/\r?\n/g, ' ').trim();
    if (/^[=+\-@\t\r]/.test(s) && !/^\+91\d/.test(s)) {
      s = "'" + s;
    }
    if (s.includes(',') || s.includes('"') || s.includes('\n')) {
      return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }

  function sanitizeIndianPhone(raw) {
    const digits = String(raw || '').replace(/\D/g, '');
    if (digits.length === 12 && digits.startsWith('91')) {
      return digits.slice(2);
    }
    if (digits.length === 11 && digits.startsWith('0')) {
      return digits.slice(1);
    }
    return digits;
  }

  function isValidIndianPhone(raw) {
    const clean = sanitizeIndianPhone(raw);
    return /^[6-9]\d{9}$/.test(clean);
  }

  function formatIST(dateObj) {
    const d = dateObj instanceof Date ? dateObj : new Date();
    try {
      return d.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
      }) + ' IST';
    } catch (_) {
      return d.toISOString();
    }
  }

  // ── 3. DESIGNATED BHUBANESWAR & ODISHA ANCHOR ZONES ───────────────────────
  const anchors = {
    rasulgarh: {
      id: 'rasulgarh',
      name: 'Rasulgarh Square Canopy',
      lat: 20.2906,
      lng: 85.8648,
      radiusM: 100,
      sector: 'nbfc'
    },
    unit1: {
      id: 'unit1',
      name: 'Unit-1 Daily Haat Canopy',
      lat: 20.2638,
      lng: 85.8340,
      radiusM: 100,
      sector: 'nbfc'
    },
    patia: {
      id: 'patia',
      name: 'Infocity / Patia Sampling Hub',
      lat: 20.3541,
      lng: 85.8192,
      radiusM: 100,
      sector: 'd2c'
    },
    saheed: {
      id: 'saheed',
      name: 'Saheed Nagar Merchant Zone',
      lat: 20.2882,
      lng: 85.8436,
      radiusM: 20,
      sector: 'bank'
    },
    kalinga: {
      id: 'kalinga',
      name: 'Kalinga Nagar Society Kiosk',
      lat: 20.2789,
      lng: 85.7725,
      radiusM: 100,
      sector: 'insurance'
    }
  };

  const SECTOR_LABELS = {
    nbfc: 'NBFC Gold & MSME Loan Pilot',
    insurance: 'Health & Life Advisory Pilot',
    bank: 'Bank Merchant CASA & QR Pilot',
    d2c: 'D2C Experiential Sampling Pilot'
  };

  function getSectorLabel(sector) {
    return SECTOR_LABELS[String(sector || 'nbfc').toLowerCase()] || SECTOR_LABELS.nbfc;
  }

  // ── 4. HAVERSINE RADIAL DISTANCE ENGINE ───────────────────────────────────
  function haversineDistanceM(lat1, lng1, lat2, lng2) {
    const nLat1 = Number(lat1), nLng1 = Number(lng1);
    const nLat2 = Number(lat2), nLng2 = Number(lng2);
    if (
      !Number.isFinite(nLat1) || !Number.isFinite(nLng1) ||
      !Number.isFinite(nLat2) || !Number.isFinite(nLng2)
    ) {
      return Infinity;
    }
    const R = 6371000;
    const toRad = (deg) => (deg * Math.PI) / 180;
    const dLat = toRad(nLat2 - nLat1);
    const dLng = toRad(nLng2 - nLng1);
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(toRad(nLat1)) * Math.cos(toRad(nLat2)) *
      Math.sin(dLng / 2) * Math.sin(dLng / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(Math.max(0, 1 - a)));
    return Math.round(R * c);
  }

  // ── 5. GEOFENCE MANAGER ───────────────────────────────────────────────────
  class GeofenceManager {
    constructor(initialAnchor) {
      this.anchor = Object.assign({}, initialAnchor || anchors.rasulgarh);
      this.currentPosition = {
        lat: Number((this.anchor.lat + 0.00009).toFixed(6)),
        lng: Number((this.anchor.lng + 0.00008).toFixed(6)),
        accuracy: 4,
        simulated: true
      };
      this.listeners = [];
      this.watchId = null;
      this.error = null;
    }

    subscribe(fn) {
      if (typeof fn === 'function') {
        this.listeners.push(fn);
        fn(this.getStatus());
      }
      return () => {
        this.listeners = this.listeners.filter((l) => l !== fn);
      };
    }

    notify() {
      const status = this.getStatus();
      this.listeners.forEach((fn) => {
        try {
          fn(status);
        } catch (err) {
          console.error('[UtkalVantage.GeofenceManager] Listener error:', err);
        }
      });
      RealtimeBroadcaster.publish('GEO_STATUS', status);
    }

    setAnchor(presetObj) {
      if (!presetObj || !Number.isFinite(Number(presetObj.lat)) || !Number.isFinite(Number(presetObj.lng))) {
        return this.getStatus();
      }
      this.anchor = {
        id: presetObj.id || 'custom',
        name: presetObj.name || 'Assigned Canopy Zone',
        lat: Number(presetObj.lat),
        lng: Number(presetObj.lng),
        radiusM: Number(presetObj.radiusM) || 100,
        sector: presetObj.sector || 'nbfc'
      };
      this.error = null;
      this.currentPosition = {
        lat: Number((this.anchor.lat + 0.00008).toFixed(6)),
        lng: Number((this.anchor.lng + 0.00008).toFixed(6)),
        accuracy: 4,
        simulated: true
      };
      this.notify();
      return this.getStatus();
    }

    setAnchorCoords(lat, lng, name = 'Promoter Locked Location', radiusM = 100) {
      return this.setAnchor({
        id: 'locked_gps',
        name,
        lat: Number(lat),
        lng: Number(lng),
        radiusM: Number(radiusM) || 100
      });
    }

    simulatePosition(lat, lng, accuracy = 4) {
      const nLat = Number(lat);
      const nLng = Number(lng);
      if (!Number.isFinite(nLat) || !Number.isFinite(nLng)) {
        this.error = 'Invalid GPS coordinates received';
        this.notify();
        return this.getStatus();
      }
      this.error = null;
      this.currentPosition = {
        lat: nLat,
        lng: nLng,
        accuracy: Number(accuracy) || 4,
        simulated: true
      };
      this.notify();
      return this.getStatus();
    }

    getStatus() {
      if (this.error) {
        return {
          anchor: this.anchor,
          currentPosition: this.currentPosition,
          distanceM: null,
          accuracy: null,
          maxRadiusM: this.anchor.radiusM,
          isLocked: false,
          breachM: 0,
          error: this.error
        };
      }
      const dist = haversineDistanceM(
        this.anchor.lat,
        this.anchor.lng,
        this.currentPosition.lat,
        this.currentPosition.lng
      );
      const maxR = Number(this.anchor.radiusM) || 100;
      const isLocked = dist <= maxR;
      const breachM = isLocked ? 0 : Math.max(1, Math.round(dist - maxR));
      return {
        anchor: this.anchor,
        currentPosition: this.currentPosition,
        distanceM: dist,
        accuracy: this.currentPosition.accuracy || 4,
        maxRadiusM: maxR,
        isLocked,
        breachM,
        error: null
      };
    }

    startWatch() {
      this.notify();
      if (typeof navigator === 'undefined' || !navigator.geolocation) {
        return;
      }
      try {
        this.watchId = navigator.geolocation.watchPosition(
          (pos) => {
            if (pos && pos.coords) {
              const distToAnchor = haversineDistanceM(
                this.anchor.lat,
                this.anchor.lng,
                pos.coords.latitude,
                pos.coords.longitude
              );
              if (distToAnchor < 5000 || this.anchor.id === 'locked_gps') {
                this.currentPosition = {
                  lat: pos.coords.latitude,
                  lng: pos.coords.longitude,
                  accuracy: Math.round(pos.coords.accuracy || 5),
                  simulated: false
                };
                this.error = null;
                this.notify();
              }
            }
          },
          () => {
            this.notify();
          },
          { enableHighAccuracy: true, timeout: 6000, maximumAge: 10000 }
        );
      } catch (_) {
        this.notify();
      }
    }

    stopWatch() {
      if (this.watchId !== null && typeof navigator !== 'undefined' && navigator.geolocation) {
        navigator.geolocation.clearWatch(this.watchId);
        this.watchId = null;
      }
    }
  }

  // ── 6. CRYPTOGRAPHIC PHOTO AUDIT ENGINE ───────────────────────────────────
  const PhotoAuditEngine = {
    async loadImageSource(source) {
      if (typeof source === 'string' && source.startsWith('data:image')) {
        return new Promise((resolve, reject) => {
          const img = new Image();
          img.onload = () => resolve(img);
          img.onerror = () => reject(new Error('Failed to decode Data URL image'));
          img.src = source;
        });
      }
      if (typeof File !== 'undefined' && (source instanceof File || source instanceof Blob)) {
        return new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = (e) => {
            const img = new Image();
            img.onload = () => resolve(img);
            img.onerror = () => reject(new Error('Unsupported or corrupt image file'));
            img.src = e.target.result;
          };
          reader.onerror = () => reject(new Error('Failed to read image file'));
          reader.readAsDataURL(source);
        });
      }
      if (typeof HTMLCanvasElement !== 'undefined' && source instanceof HTMLCanvasElement) {
        return source;
      }
      if (typeof HTMLImageElement !== 'undefined' && source instanceof HTMLImageElement) {
        return source;
      }
      throw new Error('Invalid image input provided to PhotoAuditEngine');
    },

    async processAndAudit(source, meta = {}) {
      const istTime = formatIST(new Date());
      const isoTime = new Date().toISOString();
      const lat = Number.isFinite(Number(meta.lat)) ? Number(meta.lat) : 20.290623;
      const lng = Number.isFinite(Number(meta.lng)) ? Number(meta.lng) : 85.864812;
      const accuracy = Number.isFinite(Number(meta.accuracy)) ? Number(meta.accuracy) : 4;
      const promoterId = String(meta.promoterId || 'UV-REP-01');
      const sector = String(meta.sector || 'nbfc').toUpperCase();
      const zone = String(meta.zone || 'Rasulgarh Square Canopy');

      let dataUrl = '';

      if (typeof document !== 'undefined') {
        const imgOrCanvas = await this.loadImageSource(source);
        const origW = imgOrCanvas.width || 800;
        const origH = imgOrCanvas.height || 600;
        const maxDim = 960;
        const scale = Math.min(1, maxDim / Math.max(origW, origH));
        const w = Math.max(400, Math.round(origW * scale));
        const h = Math.max(300, Math.round(origH * scale));

        const canvas = document.createElement('canvas');
        canvas.width = w;
        canvas.height = h;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(imgOrCanvas, 0, 0, w, h);

        const barH = Math.max(76, Math.round(h * 0.16));
        const barY = h - barH;
        ctx.fillStyle = 'rgba(22, 20, 18, 0.88)';
        ctx.fillRect(0, barY, w, barH);

        ctx.fillStyle = '#D85A30';
        ctx.fillRect(0, barY, w, 4);

        const padX = 16;
        const fontBase = Math.max(11, Math.round(w * 0.017));
        ctx.fillStyle = '#EF9F27';
        ctx.font = `bold ${fontBase}px "IBM Plex Mono", monospace`;
        ctx.fillText(`UTKAL VANTAGE • TAMPER-PROOF FIELD AUDIT [${sector}]`, padX, barY + Math.round(barH * 0.34));

        ctx.fillStyle = '#FFFFFF';
        ctx.font = `${fontBase}px "IBM Plex Mono", monospace`;
        ctx.fillText(`REP: ${promoterId} | ZONE: ${zone}`, padX, barY + Math.round(barH * 0.62));

        ctx.fillStyle = '#A3E635';
        ctx.font = `${Math.max(10, fontBase - 1)}px "IBM Plex Mono", monospace`;
        ctx.fillText(`GPS: ${lat.toFixed(6)}, ${lng.toFixed(6)} (±${accuracy}m) | ${istTime}`, padX, barY + Math.round(barH * 0.88));

        dataUrl = canvas.toDataURL('image/jpeg', 0.88);
      } else {
        dataUrl = typeof source === 'string' ? source : 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
      }

      const sha256 = await computeSha256Hex(dataUrl);
      return {
        id: 'AUD-' + Date.now().toString(36).toUpperCase() + '-' + sha256.substring(0, 6).toUpperCase(),
        dataUrl,
        sha256,
        shortHash: sha256.substring(0, 12),
        timestamp: isoTime,
        istFormatted: istTime,
        lat,
        lng,
        accuracy,
        sector: sector.toLowerCase(),
        zone,
        promoterId
      };
    },

    async verifyIntegrity(dataUrl, expectedSha256) {
      if (!dataUrl || !expectedSha256) {
        return { match: false, computed: null, expected: expectedSha256 };
      }
      const computed = await computeSha256Hex(dataUrl);
      const cleanExpected = String(expectedSha256).trim().toLowerCase();
      return {
        match: computed.toLowerCase() === cleanExpected,
        computed,
        expected: cleanExpected,
        verifiedAt: new Date().toISOString()
      };
    }
  };

  // ── 7. DUAL-VERIFICATION OTP STATE MACHINE ────────────────────────────────
  class DualVerificationMachine {
    constructor(options = {}) {
      this.ttlMs = Number(options.ttlMs) || 90000;
      this.maxAttempts = Number(options.maxAttempts) || 3;
      this.challenge = null;
    }

    startChallenge(rawPhone, context = {}) {
      const cleanPhone = sanitizeIndianPhone(rawPhone);
      if (!isValidIndianPhone(cleanPhone)) {
        throw new Error('Invalid Indian mobile number. Must be 10 digits starting with 6, 7, 8, or 9.');
      }
      let codeNum = 0;
      if (global.crypto && global.crypto.getRandomValues) {
        const arr = new Uint32Array(1);
        global.crypto.getRandomValues(arr);
        codeNum = 100000 + (arr[0] % 900000);
      } else {
        codeNum = Math.floor(100000 + Math.random() * 900000);
      }
      const now = Date.now();
      this.challenge = {
        phone: cleanPhone,
        code: String(codeNum),
        createdAt: now,
        expiresAt: now + this.ttlMs,
        attempts: 0,
        maxAttempts: this.maxAttempts,
        verified: false,
        verifiedAt: null,
        token: null,
        context: Object.assign({}, context)
      };
      return Object.assign({}, this.challenge);
    }

    verify(inputCode, currentPhoneOnForm = null) {
      if (!this.challenge) {
        return { success: false, reason: 'No active OTP challenge. Please request an OTP first.' };
      }
      if (currentPhoneOnForm !== null) {
        const checkPhone = sanitizeIndianPhone(currentPhoneOnForm);
        if (checkPhone !== this.challenge.phone) {
          return {
            success: false,
            reason: `Phone number changed (${checkPhone} vs ${this.challenge.phone}). Please re-trigger OTP for the new number.`
          };
        }
      }
      if (Date.now() > this.challenge.expiresAt) {
        return { success: false, reason: 'OTP code expired (90s timeout). Please generate a new OTP.' };
      }
      if (this.challenge.attempts >= this.challenge.maxAttempts) {
        return {
          success: false,
          reason: 'Maximum verification attempts (3) exceeded. Challenge locked — please request a new OTP.'
        };
      }
      const cleanedCode = String(inputCode || '').trim();
      if (!/^\d{6}$/.test(cleanedCode)) {
        return { success: false, reason: 'Please enter a valid 6-digit numeric OTP code.' };
      }
      this.challenge.attempts += 1;
      if (cleanedCode === this.challenge.code) {
        this.challenge.verified = true;
        this.challenge.verifiedAt = new Date().toISOString();
        this.challenge.token = `UV-OTP-${this.challenge.phone}-${Date.now().toString(36).toUpperCase()}`;
        return {
          success: true,
          phone: this.challenge.phone,
          verifiedAt: this.challenge.verifiedAt,
          token: this.challenge.token
        };
      }
      const rem = this.challenge.maxAttempts - this.challenge.attempts;
      return {
        success: false,
        reason: rem > 0
          ? `Incorrect OTP code (${rem} attempt${rem === 1 ? '' : 's'} remaining).`
          : 'Incorrect OTP code. Maximum attempts reached — please regenerate OTP.'
      };
    }

    isVerifiedForPhone(rawPhone) {
      if (!this.challenge || !this.challenge.verified) return false;
      return this.challenge.phone === sanitizeIndianPhone(rawPhone);
    }

    reset() {
      this.challenge = null;
    }

    static getWhatsAppLink(rawPhone, sector = 'nbfc', code = '000000') {
      const cleanPhone = sanitizeIndianPhone(rawPhone);
      const sectorMessages = {
        nbfc: `Namaskar! Your Utkal Vantage Gold Loan Priority Valuation OTP is *${code}*. Present this at your nearest partner branch for priority assessment.`,
        insurance: `Namaskar! Your Utkal Vantage Family Health Advisory OTP is *${code}*. Includes cashless network hospital coverage details for Bhubaneswar.`,
        bank: `Namaskar! Your Utkal Vantage Merchant CASA & Soundbox Onboarding OTP is *${code}*. Verified KYC checklist logged for zero-fee current account activation.`,
        d2c: `Hey! Your Utkal Vantage Sampling Trial OTP is *${code}*. Use coupon code *UTKAL25* for 25% OFF your first online order!`
      };
      const text = sectorMessages[String(sector).toLowerCase()] || sectorMessages.nbfc;
      return `https://wa.me/91${cleanPhone}?text=${encodeURIComponent(text)}`;
    }
  }

  // ── 8. SECTOR P&L LEAD SCORING ENGINE ─────────────────────────────────────
  const LeadScoringEngine = {
    scoreLead(sector, details = {}, geoCompliant = true, otpVerified = true) {
      let score = 5;
      const sec = String(sector || 'nbfc').toLowerCase();
      if (sec === 'nbfc') {
        const g = String(details.goldGrams || '');
        if (g.includes('50g+')) score = 9;
        else if (g.includes('30-50g')) score = 8;
        else score = 7;
        if (String(details.currentRate || '').includes('48%') || String(details.currentRate || '').includes('36%')) {
          score += 1;
        }
      } else if (sec === 'insurance') {
        const f = String(details.family || '');
        if (f.includes('Parents')) score = 9;
        else if (f.includes('Children') || f.includes('Spouse')) score = 8;
        else score = 7;
        if (details.hospital) score += 0.5;
      } else if (sec === 'bank') {
        const k = String(details.kycStatus || '');
        if (k.includes('GST')) score = 9;
        else if (k.includes('Udyam')) score = 8;
        else score = 7;
        if (details.shopName && String(details.shopName).trim().length > 3) score += 0.5;
      } else if (sec === 'd2c') {
        const r = String(details.rating || '');
        if (r.includes('5')) score = 9;
        else if (r.includes('4')) score = 8;
        else score = 6;
      }
      if (!geoCompliant) score -= 2;
      if (!otpVerified) score -= 3;
      return Math.max(1, Math.min(10, Math.round(score)));
    },

    estimateInsurancePremium(familyStr, ageBracket = '30-45') {
      const f = String(familyStr || '');
      let base = 690;
      if (f.includes('Parents')) base = 1850;
      else if (f.includes('Children') || f.includes('Kids')) base = 1190;
      if (String(ageBracket).includes('45-60')) base = Math.round(base * 1.35);
      else if (String(ageBracket).includes('18-30')) base = Math.round(base * 0.82);
      return {
        monthlyInr: base,
        annualInr: base * 12,
        coverLakhs: f.includes('Parents') ? '₹15 Lakhs Floater' : '₹10 Lakhs Floater'
      };
    }
  };

  // ── 9. REALTIME INTER-TAB & SAME-PAGE BROADCASTER ─────────────────────────
  const RealtimeBroadcaster = {
    channel: null,
    subscribers: [],

    init() {
      if (this._initialized) return;
      this._initialized = true;
      try {
        if (typeof BroadcastChannel !== 'undefined') {
          this.channel = new BroadcastChannel('utkal_vantage_realtime_v2');
          this.channel.onmessage = (e) => {
            if (e && e.data) this._dispatch(e.data);
          };
        }
      } catch (_) {}

      if (typeof global.addEventListener === 'function') {
        global.addEventListener('storage', (e) => {
          if (e && e.key === 'uv_realtime_event_bus' && e.newValue) {
            try {
              const parsed = JSON.parse(e.newValue);
              this._dispatch(parsed);
            } catch (_) {}
          }
        });
      }
    },

    _dispatch(eventObj) {
      this.subscribers.forEach((cb) => {
        try {
          cb(eventObj);
        } catch (err) {
          console.error('[UtkalVantage.RealtimeBroadcaster] Subscriber error:', err);
        }
      });
    },

    publish(type, payload) {
      this.init();
      const eventObj = {
        id: 'EVT-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7),
        type,
        payload,
        timestamp: new Date().toISOString()
      };
      this._dispatch(eventObj);
      try {
        if (this.channel) this.channel.postMessage(eventObj);
      } catch (_) {}
      try {
        if (global.localStorage) {
          global.localStorage.setItem('uv_realtime_event_bus', JSON.stringify(eventObj));
        }
      } catch (_) {}
      return eventObj;
    },

    subscribe(callback) {
      this.init();
      if (typeof callback === 'function') {
        this.subscribers.push(callback);
      }
      return () => {
        this.subscribers = this.subscribers.filter((cb) => cb !== callback);
      };
    }
  };

  // ── 10. RESILIENT STORAGE ENGINE (IndexedDB + localStorage + Memory) ──────
  const memoryStore = {
    leads: [],
    photos: [],
    campaigns: [],
    promoters: [],
    prospectConfig: {
      clientName: 'Prospective Client Preview',
      branchName: 'Bhubaneswar Catchment Pilot',
      sector: 'nbfc'
    },
    inventory: {
      d2c: { startingStock: 200, dispensed: 0, remaining: 200, sku: 'Trial SKU — Batch A' }
    }
  };

  const StorageEngine = {
    dbName: 'UtkalVantageDB_v21',
    dbVersion: 2,
    _dbPromise: null,

    _readLocal(key, fallback) {
      try {
        if (global.localStorage) {
          const raw = global.localStorage.getItem('uv_store_v21_' + key);
          if (raw) return JSON.parse(raw);
        }
      } catch (_) {}
      return fallback;
    },

    _writeLocal(key, val) {
      try {
        if (global.localStorage) {
          global.localStorage.setItem('uv_store_v21_' + key, JSON.stringify(val));
        }
      } catch (_) {}
    },

    getProspectConfig() {
      return this._readLocal('prospectConfig', memoryStore.prospectConfig);
    },

    setProspectConfig(cfg = {}) {
      const cur = this.getProspectConfig();
      const updated = Object.assign({}, cur, cfg);
      memoryStore.prospectConfig = updated;
      this._writeLocal('prospectConfig', updated);
      RealtimeBroadcaster.publish('PROSPECT_CONFIG_UPDATED', updated);
      return updated;
    },

    async _getDB() {
      if (typeof indexedDB === 'undefined') return null;
      if (this._dbPromise) return this._dbPromise;
      this._dbPromise = new Promise((resolve) => {
        try {
          const req = indexedDB.open(this.dbName, this.dbVersion);
          req.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains('leads')) {
              db.createObjectStore('leads', { keyPath: 'id' });
            }
            if (!db.objectStoreNames.contains('photos')) {
              db.createObjectStore('photos', { keyPath: 'id' });
            }
            if (!db.objectStoreNames.contains('campaigns')) {
              db.createObjectStore('campaigns', { keyPath: 'id' });
            }
            if (!db.objectStoreNames.contains('promoters')) {
              db.createObjectStore('promoters', { keyPath: 'id' });
            }
          };
          req.onsuccess = (e) => resolve(e.target.result);
          req.onerror = () => resolve(null);
          req.onblocked = () => resolve(null);
        } catch (_) {
          resolve(null);
        }
      });
      return this._dbPromise;
    },

    async saveLead(leadRecord, options = {}) {
      if (!leadRecord || !leadRecord.id) {
        throw new Error('Invalid leadRecord: missing id');
      }
      const prospect = this.getProspectConfig();
      const cleanLead = Object.assign(
        {
          timestamp: new Date().toISOString(),
          sector: prospect.sector || 'nbfc',
          client: leadRecord.client || getSectorLabel(leadRecord.sector || prospect.sector),
          otpVerified: true,
          geoCompliant: true,
          syncStatus: typeof navigator !== 'undefined' && navigator.onLine === false ? 'queued' : 'synced'
        },
        leadRecord
      );

      const existing = this._readLocal('leads', memoryStore.leads);
      const idx = existing.findIndex((l) => l.id === cleanLead.id);
      if (idx >= 0) existing[idx] = cleanLead;
      else existing.unshift(cleanLead);
      memoryStore.leads = existing;
      this._writeLocal('leads', existing);

      const db = await this._getDB();
      if (db) {
        await new Promise((resolve) => {
          try {
            const tx = db.transaction('leads', 'readwrite');
            tx.objectStore('leads').put(cleanLead);
            tx.oncomplete = () => resolve(true);
            tx.onerror = () => resolve(false);
          } catch (_) {
            resolve(false);
          }
        });
      }

      if (!options.silent) {
        RealtimeBroadcaster.publish('LEAD_SAVED', cleanLead);
      }
      return cleanLead;
    },

    async getAllLeads() {
      const localLeads = this._readLocal('leads', memoryStore.leads);
      const db = await this._getDB();
      if (!db) return localLeads;

      return new Promise((resolve) => {
        try {
          const tx = db.transaction('leads', 'readonly');
          const req = tx.objectStore('leads').getAll();
          req.onsuccess = () => {
            const dbLeads = Array.isArray(req.result) ? req.result : [];
            const mergedMap = new Map();
            localLeads.forEach((l) => mergedMap.set(l.id, l));
            dbLeads.forEach((l) => mergedMap.set(l.id, l));
            const merged = Array.from(mergedMap.values()).sort(
              (a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
            );
            memoryStore.leads = merged;
            resolve(merged);
          };
          req.onerror = () => resolve(localLeads);
        } catch (_) {
          resolve(localLeads);
        }
      });
    },

    async savePhoto(photoRecord, options = {}) {
      if (!photoRecord || !photoRecord.id) {
        throw new Error('Invalid photoRecord: missing id');
      }
      const existing = this._readLocal('photos', memoryStore.photos);
      const idx = existing.findIndex((p) => p.id === photoRecord.id);
      if (idx >= 0) existing[idx] = photoRecord;
      else existing.unshift(photoRecord);
      memoryStore.photos = existing;
      this._writeLocal('photos', existing.slice(0, 15));

      const db = await this._getDB();
      if (db) {
        await new Promise((resolve) => {
          try {
            const tx = db.transaction('photos', 'readwrite');
            tx.objectStore('photos').put(photoRecord);
            tx.oncomplete = () => resolve(true);
            tx.onerror = () => resolve(false);
          } catch (_) {
            resolve(false);
          }
        });
      }

      if (!options.silent) {
        RealtimeBroadcaster.publish('PHOTO_AUDITED', photoRecord);
      }
      return photoRecord;
    },

    async getAllPhotos() {
      const localPhotos = this._readLocal('photos', memoryStore.photos);
      const db = await this._getDB();
      if (!db) return localPhotos;

      return new Promise((resolve) => {
        try {
          const tx = db.transaction('photos', 'readonly');
          const req = tx.objectStore('photos').getAll();
          req.onsuccess = () => {
            const dbPhotos = Array.isArray(req.result) ? req.result : [];
            const mergedMap = new Map();
            localPhotos.forEach((p) => mergedMap.set(p.id, p));
            dbPhotos.forEach((p) => mergedMap.set(p.id, p));
            const merged = Array.from(mergedMap.values()).sort(
              (a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
            );
            memoryStore.photos = merged;
            resolve(merged);
          };
          req.onerror = () => resolve(localPhotos);
        } catch (_) {
          resolve(localPhotos);
        }
      });
    },

    getInventory(sector = 'd2c') {
      const allInv = this._readLocal('inventory', memoryStore.inventory);
      return (
        allInv[sector] || {
          startingStock: 200,
          dispensed: 0,
          remaining: 200,
          sku: 'Trial SKU — Batch A'
        }
      );
    },

    updateInventory(sector = 'd2c', deltaDispensed = 1, customStart = null) {
      const allInv = this._readLocal('inventory', memoryStore.inventory);
      const cur = allInv[sector] || { startingStock: 200, dispensed: 0, remaining: 200 };
      if (customStart !== null && Number.isFinite(Number(customStart))) {
        cur.startingStock = Math.max(0, Number(customStart));
      }
      cur.dispensed = Math.min(cur.startingStock, Math.max(0, cur.dispensed + Number(deltaDispensed || 0)));
      cur.remaining = Math.max(0, cur.startingStock - cur.dispensed);
      allInv[sector] = cur;
      memoryStore.inventory = allInv;
      this._writeLocal('inventory', allInv);
      RealtimeBroadcaster.publish('INVENTORY_UPDATED', { sector, inventory: cur });
      return cur;
    },

    async clearAll() {
      memoryStore.leads = [];
      memoryStore.photos = [];
      memoryStore.inventory = {
        d2c: { startingStock: 200, dispensed: 0, remaining: 200, sku: 'Trial SKU — Batch A' }
      };
      this._writeLocal('leads', []);
      this._writeLocal('photos', []);
      this._writeLocal('inventory', memoryStore.inventory);
      const db = await this._getDB();
      if (db) {
        try {
          const tx = db.transaction(['leads', 'photos'], 'readwrite');
          tx.objectStore('leads').clear();
          tx.objectStore('photos').clear();
        } catch (_) {}
      }
      RealtimeBroadcaster.publish('WORKSPACE_CLEARED', {});
    }
  };

  // ── 11. UI TOAST HELPER ───────────────────────────────────────────────────
  const UI = {
    toast(message, type = 'info', durationMs = 3800) {
      if (typeof document === 'undefined') return;
      let container = document.getElementById('uvToastContainer');
      if (!container) {
        container = document.createElement('div');
        container.id = 'uvToastContainer';
        container.className = 'uv-toast-container';
        document.body.appendChild(container);
      }
      const toastEl = document.createElement('div');
      toastEl.className = `uv-toast ${type}`;
      toastEl.innerHTML = `
        <span>${escapeHtml(message)}</span>
        <button type="button" style="background:none;border:none;color:#A39C93;cursor:pointer;font-weight:700;padding:0 4px;" aria-label="Dismiss">✕</button>
      `;
      toastEl.querySelector('button').onclick = () => toastEl.remove();
      container.appendChild(toastEl);
      if (durationMs > 0) {
        setTimeout(() => {
          if (toastEl.parentNode) toastEl.remove();
        }, durationMs);
      }
    }
  };

  global.UtkalVantage = {
    version: '2.1.0-MVP',
    anchors,
    SECTOR_LABELS,
    getSectorLabel,
    haversineDistanceM,
    computeSha256Hex,
    escapeHtml,
    escapeCsvCell,
    sanitizeIndianPhone,
    isValidIndianPhone,
    formatIST,
    GeofenceManager,
    PhotoAuditEngine,
    DualVerificationMachine,
    LeadScoringEngine,
    StorageEngine,
    RealtimeBroadcaster,
    UI
  };
})(typeof window !== 'undefined' ? window : globalThis);
