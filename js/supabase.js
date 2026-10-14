/**
 * ============================================================================
 * UTKAL VANTAGE — SUPABASE CLOUD & OFFLINE-FIRST REST CLIENT (js/supabase.js)
 * Zero-dependency REST bridge for Supabase Auth, Postgres & Storage.
 * Automatically falls back to local IndexedDB/StorageEngine when offline
 * or before production Supabase credentials are configured.
 * ============================================================================
 */
(function (global) {
  'use strict';

  const SUPABASE_CONFIG = {
    url: 'https://your-project-ref.supabase.co',
    anonKey: '' // Paste your Supabase public anon key here for cloud sync
  };

  class UtkalSupabaseClient {
    constructor(config) {
      this.url = (config && config.url) || SUPABASE_CONFIG.url;
      this.anonKey = (config && config.anonKey) || SUPABASE_CONFIG.anonKey;
    }

    isConfigured() {
      return Boolean(
        this.anonKey &&
        this.anonKey.length > 20 &&
        this.url &&
        !this.url.includes('your-project-ref')
      );
    }

    async request(path, options = {}) {
      if (!this.isConfigured() || (typeof navigator !== 'undefined' && !navigator.onLine)) {
        return { data: null, offlineFallback: true, error: null };
      }
      try {
        const headers = Object.assign(
          {
            'Content-Type': 'application/json',
            apikey: this.anonKey,
            Authorization: `Bearer ${this.anonKey}`,
            Prefer: 'return=representation'
          },
          options.headers || {}
        );
        const res = await fetch(`${this.url}/rest/v1/${path}`, {
          method: options.method || 'GET',
          headers,
          body: options.body ? JSON.stringify(options.body) : undefined
        });
        if (!res.ok) {
          const errText = await res.text();
          return { data: null, offlineFallback: false, error: errText };
        }
        const data = await res.json();
        return { data, offlineFallback: false, error: null };
      } catch (err) {
        return { data: null, offlineFallback: true, error: err.message };
      }
    }

    async syncLead(leadRecord) {
      if (global.UtkalVantage && global.UtkalVantage.StorageEngine) {
        await global.UtkalVantage.StorageEngine.saveLead(leadRecord, { silent: true });
      }
      return this.request('leads', { method: 'POST', body: leadRecord });
    }

    async fetchLeads() {
      const cloud = await this.request('leads?select=*&order=timestamp.desc');
      if (cloud.data && Array.isArray(cloud.data)) {
        return cloud.data;
      }
      if (global.UtkalVantage && global.UtkalVantage.StorageEngine) {
        return global.UtkalVantage.StorageEngine.getAllLeads();
      }
      return [];
    }
  }

  global.UtkalSupabase = new UtkalSupabaseClient(SUPABASE_CONFIG);
})(typeof window !== 'undefined' ? window : globalThis);
