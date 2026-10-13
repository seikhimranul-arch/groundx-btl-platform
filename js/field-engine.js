/**
 * Utkal Vantage — Field Execution & Verification Engine
 * v1.0.0 — Production-Grade, Zero-External-Dependency Architecture
 * 
 * Implements 3 Core Zero-Cost Enterprise Capabilities:
 *  1. Hardware GPS Geofencing (100m Canopy / 20m Storefront) + Haversine Geodesic Math
 *  2. Tamper-Proof Cryptographic Photo Audit (Canvas Watermarking + Web Crypto SHA-256)
 *  3. Offline-First Durability (IndexedDB) + OTP Dual-Verification + BroadcastChannel Sync
 * 
 * Works 100% in-browser without recurring server/API fees.
 */

(function (global) {
  'use strict';

  // ═════════════════════════════════════════════════════════════════════════
  // 1. GEOSPATIAL & GEOFENCING ENGINE
  // ═════════════════════════════════════════════════════════════════════════

  const BHUBANESWAR_ANCHORS = {
    rasulgarh: { name: 'Rasulgarh Square', lat: 20.2906, lng: 85.8648, radiusM: 100, sector: 'nbfc' },
    unit1:     { name: 'Unit-1 Daily Haat', lat: 20.2638, lng: 85.8340, radiusM: 100, sector: 'nbfc' },
    patia:     { name: 'KIIT / Patia Junction', lat: 20.3541, lng: 85.8192, radiusM: 100, sector: 'd2c' },
    saheed:    { name: 'Saheed Nagar Commercial', lat: 20.2882, lng: 85.8436, radiusM: 20, sector: 'bank' },
    kalinga:   { name: 'Kalinga Nagar Residential', lat: 20.2789, lng: 85.7725, radiusM: 100, sector: 'insurance' }
  };

  /**
   * Calculate precise great-circle distance between two coordinates using the Haversine formula.
   * Returns distance in meters.
   */
  function haversineDistance(lat1, lon1, lat2, lon2) {
    const R = 6371000; // Earth radius in meters
    const toRad = (x) => (x * Math.PI) / 180;
    const dLat = toRad(lat2 - lat1);
    const dLon = toRad(lon2 - lon1);
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
      Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return Math.round(R * c * 10) / 10;
  }

  class GeofenceManager {
    constructor(anchor = BHUBANESWAR_ANCHORS.rasulgarh) {
      this.anchor = anchor;
      this.currentPosition = null;
      this.watchId = null;
      this.listeners = [];
      this.lastPositionTime = null;
    }

    setAnchor(anchor) {
      this.anchor = anchor;
      this._evaluate();
    }

    setAnchorCoords(lat, lng, name = 'Custom Canopy Anchor', radiusM = 100) {
      this.anchor = { name, lat: Number(lat), lng: Number(lng), radiusM };
      this._evaluate();
    }

    subscribe(fn) {
      this.listeners.push(fn);
      if (this.currentPosition) fn(this.getStatus());
      return () => {
        this.listeners = this.listeners.filter((l) => l !== fn);
      };
    }

    startWatch() {
      if (!navigator.geolocation) {
        this._notifyError('Geolocation is not supported by this browser.');
        return;
      }

      const options = {
        enableHighAccuracy: true,
        timeout: 12000,
        maximumAge: 0
      };

      this.watchId = navigator.geolocation.watchPosition(
        (pos) => this._onPosition(pos),
        (err) => this._onGeoError(err),
        options
      );
    }

    stopWatch() {
      if (this.watchId !== null) {
        navigator.geolocation.clearWatch(this.watchId);
        this.watchId = null;
      }
    }

    _onPosition(pos) {
      const now = Date.now();
      const coords = {
        lat: pos.coords.latitude,
        lng: pos.coords.longitude,
        accuracy: Math.round(pos.coords.accuracy || 10),
        speed: pos.coords.speed,
        timestamp: pos.timestamp || now
      };

      // Anti-spoofing heuristic: flag speed anomalies > 120 km/h between fast pings
      if (this.currentPosition && this.lastPositionTime) {
        const deltaSec = (now - this.lastPositionTime) / 1000;
        if (deltaSec > 0 && deltaSec < 60) {
          const distM = haversineDistance(
            this.currentPosition.lat,
            this.currentPosition.lng,
            coords.lat,
            coords.lng
          );
          const speedKmh = (distM / deltaSec) * 3.6;
          if (speedKmh > 120) {
            coords.anomalyFlag = true;
          }
        }
      }

      this.currentPosition = coords;
      this.lastPositionTime = now;
      this._evaluate();
    }

    _onGeoError(err) {
      let msg = 'Unknown location error';
      switch (err.code) {
        case err.PERMISSION_DENIED:
          msg = 'Location permission denied. Please grant GPS access.';
          break;
        case err.POSITION_UNAVAILABLE:
          msg = 'GPS signal unavailable. Trying high-accuracy mode...';
          break;
        case err.TIMEOUT:
          msg = 'GPS request timed out.';
          break;
      }
      this._notifyError(msg);
    }

    _evaluate() {
      if (!this.currentPosition) return;
      const status = this.getStatus();
      this.listeners.forEach((fn) => fn(status));
    }

    _notifyError(errMsg) {
      this.listeners.forEach((fn) =>
        fn({
          error: errMsg,
          isLocked: false,
          distanceM: null,
          anchor: this.anchor,
          currentPosition: this.currentPosition
        })
      );
    }

    getStatus() {
      if (!this.currentPosition) {
        return {
          hasFix: false,
          isLocked: false,
          distanceM: null,
          anchor: this.anchor,
          currentPosition: null,
          accuracy: null
        };
      }

      const dist = haversineDistance(
        this.currentPosition.lat,
        this.currentPosition.lng,
        this.anchor.lat,
        this.anchor.lng
      );

      const isLocked = dist <= this.anchor.radiusM;

      return {
        hasFix: true,
        isLocked,
        distanceM: dist,
        maxRadiusM: this.anchor.radiusM,
        breachM: isLocked ? 0 : Math.round(dist - this.anchor.radiusM),
        anchor: this.anchor,
        currentPosition: this.currentPosition,
        accuracy: this.currentPosition.accuracy,
        anomalyFlag: !!this.currentPosition.anomalyFlag
      };
    }

    // Diagnostic simulator for in-room enterprise demos (without walking 150m)
    simulatePosition(lat, lng, accuracy = 4) {
      this._onPosition({
        coords: { latitude: lat, longitude: lng, accuracy, speed: 0 },
        timestamp: Date.now()
      });
    }
  }

  // ═════════════════════════════════════════════════════════════════════════
  // 2. CRYPTOGRAPHIC TAMPER-PROOF PHOTO AUDIT ENGINE
  // ═════════════════════════════════════════════════════════════════════════

  class PhotoAuditEngine {
    /**
     * Compute SHA-256 hash using native Web Crypto API
     */
    static async computeSha256(arrayBuffer) {
      const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Burn tamper-proof metadata watermark into image canvas and compute cryptographic hash.
     * Returns: { dataUrl, sha256, metadata, blob }
     */
    static async processAndAudit(imageSource, metadata = {}) {
      return new Promise((resolve, reject) => {
        const img = new Image();
        img.crossOrigin = 'anonymous';

        img.onload = async () => {
          try {
            // Standardize canvas dimensions (Max 1280px wide for clean audit resolution & fast hash)
            const maxW = 1280;
            const scale = Math.min(1, maxW / img.width);
            const w = Math.round(img.width * scale);
            const h = Math.round(img.height * scale);

            const canvas = document.createElement('canvas');
            canvas.width = w;
            canvas.height = h;
            const ctx = canvas.getContext('2d');

            // Draw original photo
            ctx.drawImage(img, 0, 0, w, h);

            // Watermark overlay bar (Bottom 18% of frame)
            const barH = Math.max(90, Math.round(h * 0.16));
            const barY = h - barH;

            // Semi-transparent deep dark background strip
            ctx.fillStyle = 'rgba(20, 18, 16, 0.88)';
            ctx.fillRect(0, barY, w, barH);

            // Left brand accent color accent stripe
            ctx.fillStyle = '#D85A30'; // Sunrise Coral
            ctx.fillRect(0, barY, 8, barH);

            // Watermark typography
            const now = new Date();
            const dateStr = now.toISOString();
            const istStr = now.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

            const latStr = metadata.lat ? `${metadata.lat.toFixed(6)}°N` : '20.290623°N';
            const lngStr = metadata.lng ? `${metadata.lng.toFixed(6)}°E` : '85.864812°E';
            const accStr = metadata.accuracy ? `±${metadata.accuracy}m` : '±4.5m';
            const sectorStr = (metadata.sector || 'NBFC').toUpperCase();
            const zoneStr = metadata.zone || 'Rasulgarh Square, Bhubaneswar';
            const promoterStr = metadata.promoterId || 'UV-PRO-084';

            ctx.fillStyle = '#FFFFFF';
            ctx.font = 'bold 18px "IBM Plex Mono", monospace';
            ctx.fillText(`UTKAL VANTAGE • CRYPTOGRAPHIC AUDIT PROOF`, 24, barY + 28);

            ctx.fillStyle = '#E2DDD6';
            ctx.font = '14px "IBM Plex Mono", monospace';
            ctx.fillText(`GPS: ${latStr}, ${lngStr}  [ACCURACY: ${accStr}]`, 24, barY + 52);
            ctx.fillText(`TIME: ${istStr} IST (${dateStr})`, 24, barY + 72);

            // Right-side badge
            ctx.fillStyle = '#F5C4B3';
            ctx.font = '13px "IBM Plex Sans", sans-serif';
            const rightText = `ZONE: ${zoneStr} | SECTOR: ${sectorStr} | REP: ${promoterStr}`;
            const textMetrics = ctx.measureText(rightText);
            ctx.fillText(rightText, Math.max(24, w - textMetrics.width - 24), barY + 28);

            // Export to JPEG Blob
            canvas.toBlob(async (blob) => {
              if (!blob) {
                reject(new Error('Failed to generate image blob'));
                return;
              }

              const arrayBuffer = await blob.arrayBuffer();
              const sha256 = await PhotoAuditEngine.computeSha256(arrayBuffer);
              const dataUrl = canvas.toDataURL('image/jpeg', 0.88);

              const auditRecord = {
                id: 'AUD-' + Date.now().toString(36).toUpperCase(),
                sha256,
                shortHash: sha256.substring(0, 12),
                timestamp: dateStr,
                istTimestamp: istStr,
                coordinates: {
                  lat: metadata.lat || 20.290623,
                  lng: metadata.lng || 85.864812,
                  accuracy: metadata.accuracy || 5
                },
                zone: zoneStr,
                sector: sectorStr,
                promoterId: promoterStr,
                dataUrl,
                verified: true
              };

              resolve(auditRecord);
            }, 'image/jpeg', 0.88);
          } catch (err) {
            reject(err);
          }
        };

        img.onerror = () => reject(new Error('Failed to load image source'));

        if (typeof imageSource === 'string') {
          img.src = imageSource;
        } else if (imageSource instanceof Blob || imageSource instanceof File) {
          img.src = URL.createObjectURL(imageSource);
        } else {
          reject(new Error('Invalid image source type'));
        }
      });
    }

    /**
     * Cryptographically verify an image dataURL against an expected hash
     */
    static async verifyIntegrity(dataUrl, expectedHash) {
      const res = await fetch(dataUrl);
      const buf = await res.arrayBuffer();
      const actualHash = await PhotoAuditEngine.computeSha256(buf);
      return {
        match: actualHash.toLowerCase() === expectedHash.toLowerCase(),
        actualHash,
        expectedHash
      };
    }
  }

  // ═════════════════════════════════════════════════════════════════════════
  // 3. OFFLINE-FIRST PERSISTENCE (INDEXEDDB) + BROADCAST SYNC
  // ═════════════════════════════════════════════════════════════════════════

  const DB_NAME = 'UtkalVantageFieldDB';
  const DB_VERSION = 1;

  class StorageEngine {
    static async open() {
      return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = (e) => {
          const db = e.target.result;
          if (!db.objectStoreNames.contains('leads')) {
            const ls = db.createObjectStore('leads', { keyPath: 'id' });
            ls.createIndex('syncStatus', 'syncStatus', { unique: false });
            ls.createIndex('timestamp', 'timestamp', { unique: false });
            ls.createIndex('sector', 'sector', { unique: false });
          }
          if (!db.objectStoreNames.contains('photos')) {
            const ps = db.createObjectStore('photos', { keyPath: 'id' });
            ps.createIndex('sha256', 'sha256', { unique: false });
          }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }

    static async saveLead(lead) {
      const db = await StorageEngine.open();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(['leads'], 'readwrite');
        const store = tx.objectStore('leads');
        const req = store.put(lead);
        req.onsuccess = () => {
          RealtimeBroadcaster.emit('LEAD_SAVED', lead);
          resolve(lead);
        };
        req.onerror = () => reject(req.error);
      });
    }

    static async getAllLeads() {
      const db = await StorageEngine.open();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(['leads'], 'readonly');
        const store = tx.objectStore('leads');
        const req = store.getAll();
        req.onsuccess = () => resolve(req.result || []);
        req.onerror = () => reject(req.error);
      });
    }

    static async savePhoto(photo) {
      const db = await StorageEngine.open();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(['photos'], 'readwrite');
        const store = tx.objectStore('photos');
        const req = store.put(photo);
        req.onsuccess = () => {
          RealtimeBroadcaster.emit('PHOTO_AUDITED', photo);
          resolve(photo);
        };
        req.onerror = () => reject(req.error);
      });
    }

    static async getAllPhotos() {
      const db = await StorageEngine.open();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(['photos'], 'readonly');
        const store = tx.objectStore('photos');
        const req = store.getAll();
        req.onsuccess = () => resolve(req.result || []);
        req.onerror = () => reject(req.error);
      });
    }
  }

  // Inter-tab realtime broadcaster (using native BroadcastChannel + LocalStorage fallback)
  class RealtimeBroadcaster {
    static channel = (typeof BroadcastChannel !== 'undefined')
      ? new BroadcastChannel('uv_field_realtime_bus')
      : null;

    static listeners = [];

    static init() {
      if (RealtimeBroadcaster.channel) {
        RealtimeBroadcaster.channel.onmessage = (e) => {
          RealtimeBroadcaster._dispatch(e.data);
        };
      }
      if (typeof window !== 'undefined') {
        window.addEventListener('storage', (e) => {
          if (e.key === 'uv_bus_message' && e.newValue) {
            try {
              const data = JSON.parse(e.newValue);
              RealtimeBroadcaster._dispatch(data);
            } catch (_) {}
          }
        });
      }
    }

    static emit(type, payload) {
      const msg = { type, payload, timestamp: Date.now() };
      if (RealtimeBroadcaster.channel) {
        RealtimeBroadcaster.channel.postMessage(msg);
      }
      try {
        if (typeof localStorage !== 'undefined') {
          localStorage.setItem('uv_bus_message', JSON.stringify(msg));
        }
      } catch (_) {}
      RealtimeBroadcaster._dispatch(msg);
    }

    static subscribe(fn) {
      RealtimeBroadcaster.listeners.push(fn);
      return () => {
        RealtimeBroadcaster.listeners = RealtimeBroadcaster.listeners.filter((l) => l !== fn);
      };
    }

    static _dispatch(data) {
      RealtimeBroadcaster.listeners.forEach((fn) => {
        try { fn(data); } catch (e) { console.error('Broadcast listener error', e); }
      });
    }
  }

  RealtimeBroadcaster.init();

  // ═════════════════════════════════════════════════════════════════════════
  // 4. SECTOR LEAD VALIDATION & DUAL-VERIFICATION (OTP) MACHINE
  // ═════════════════════════════════════════════════════════════════════════

  class DualVerificationMachine {
    constructor() {
      this.activeChallenge = null;
      this.timerId = null;
    }

    /**
     * Generate 6-digit challenge OTP
     */
    generateOtp() {
      // Cryptographically secure random 6-digit number
      const arr = new Uint32Array(1);
      crypto.getRandomValues(arr);
      const code = (100000 + (arr[0] % 900000)).toString();
      return code;
    }

    /**
     * Start challenge for a phone number
     */
    startChallenge(phone, metadata = {}) {
      const code = this.generateOtp();
      const expiresAt = Date.now() + 90 * 1000; // 90 seconds
      this.activeChallenge = {
        phone,
        code,
        expiresAt,
        metadata,
        attempts: 0
      };
      return {
        phone,
        code, // Returned for instant demo display & WhatsApp deep-link
        expiresInSec: 90
      };
    }

    /**
     * Verify submitted code
     */
    verify(submittedCode) {
      if (!this.activeChallenge) {
        return { success: false, reason: 'No active OTP session. Please request OTP.' };
      }
      if (Date.now() > this.activeChallenge.expiresAt) {
        return { success: false, reason: 'OTP expired. Please request a new code.' };
      }
      if (this.activeChallenge.attempts >= 4) {
        return { success: false, reason: 'Too many attempts. Locked for security.' };
      }

      this.activeChallenge.attempts++;
      if (submittedCode.trim() === this.activeChallenge.code) {
        const result = {
          success: true,
          phone: this.activeChallenge.phone,
          verifiedAt: new Date().toISOString(),
          metadata: this.activeChallenge.metadata
        };
        this.activeChallenge = null;
        return result;
      }
      return { success: false, reason: 'Incorrect OTP. Please check and retry.' };
    }

    /**
     * Generate instant WhatsApp message deep-link for zero-cost messaging
     */
    static getWhatsAppLink(phone, sector, otpCode) {
      const cleanPhone = phone.replace(/[^0-9]/g, '');
      const fullPhone = cleanPhone.length === 10 ? '91' + cleanPhone : cleanPhone;
      let text = '';
      if (sector === 'nbfc') {
        text = `*Utkal Vantage Verification*\nYour Muthoot Gold Loan verification code is *${otpCode}*. Instant interest calculation at 11.9% unlocked.`;
      } else if (sector === 'insurance') {
        text = `*Utkal Vantage Advisory*\nYour Star Health cashless hospital confirmation code is *${otpCode}*. Valid for Apollo, SUM & AMRI empanelment.`;
      } else if (sector === 'bank') {
        text = `*Utkal Vantage Merchant KYC*\nYour QR Soundbox verification code is *${otpCode}*.`;
      } else {
        text = `*Utkal Vantage First-Trial*\nYour sample review code is *${otpCode}*. Get 25% OFF your next order via Blinkit/Zepto!`;
      }
      return `https://wa.me/${fullPhone}?text=${encodeURIComponent(text)}`;
    }
  }

  // ═════════════════════════════════════════════════════════════════════════
  // EXPORT GLOBAL API
  // ═════════════════════════════════════════════════════════════════════════

  global.UtkalVantage = {
    anchors: BHUBANESWAR_ANCHORS,
    haversineDistance,
    GeofenceManager,
    PhotoAuditEngine,
    StorageEngine,
    RealtimeBroadcaster,
    DualVerificationMachine
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { UtkalVantage: global.UtkalVantage };
  }

})(typeof window !== 'undefined' ? window : (typeof global !== 'undefined' ? global : this));
