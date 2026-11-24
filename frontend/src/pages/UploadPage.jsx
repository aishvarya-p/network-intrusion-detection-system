import React, { useState, useRef } from 'react';
import { UploadCloud, FileText, CheckCircle2, AlertCircle, RefreshCw, Download, Info } from 'lucide-react';
import { api } from '../services/api';

export default function UploadPage({ onUploadSuccess }) {
  const [file, setFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [result, setResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const droppedFile = e.dataTransfer.files[0];
      validateAndSetFile(droppedFile);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (selectedFile) => {
    setErrorMessage(null);
    setResult(null);

    if (!selectedFile.name.toLowerCase().endsWith('.csv')) {
      setErrorMessage('Invalid file type. Please upload a .csv file.');
      setFile(null);
      return;
    }

    if (selectedFile.size > 5 * 1024 * 1024) {
      setErrorMessage('File size exceeds the 5 MB upload limit.');
      setFile(null);
      return;
    }

    setFile(selectedFile);
  };

  const handleUpload = async () => {
    if (!file) return;

    setIsUploading(true);
    setErrorMessage(null);
    setResult(null);

    try {
      const response = await api.uploadCsv(file);
      setResult(response);
      if (onUploadSuccess) onUploadSuccess();
    } catch (err) {
      setErrorMessage(err.message || 'Failed to parse and upload CSV dataset.');
    } finally {
      setIsUploading(false);
    }
  };

  const handleLoadSample = async () => {
    const sampleCsvContent = `source_ip,destination_ip,source_port,destination_port,protocol,packet_count,byte_count,duration,tcp_flags
192.168.1.101,10.0.0.10,51234,443,TCP,45,28400,2.15,ACK
192.168.1.102,10.0.0.5,52341,53,UDP,2,148,0.02,NONE
198.51.100.99,10.0.0.10,40112,22,TCP,1,48,0.005,SYN
198.51.100.99,10.0.0.10,40113,80,TCP,1,48,0.004,SYN
203.0.113.120,10.0.0.10,61223,80,TCP,2500,120000,0.12,SYN
192.168.1.115,203.0.113.78,59821,8080,TCP,8500,12500000,45.2,ACK
192.168.1.108,10.0.0.10,56234,443,TCP,75,62000,3.8,ACK`;

    const blob = new Blob([sampleCsvContent], { type: 'text/csv' });
    const sampleFile = new File([blob], 'sample_network_traffic.csv', { type: 'text/csv' });
    validateAndSetFile(sampleFile);
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="border-b border-gray-800 pb-4">
        <h2 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
          <UploadCloud className="w-5 h-5 text-cyan-400" />
          <span>Ingest Network Traffic Dataset (CSV)</span>
        </h2>
        <p className="text-xs text-gray-400 mt-0.5">
          Upload historical flow records to execute the dual-engine ML and heuristic detection pipeline.
        </p>
      </div>

      {/* Drag & Drop Zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`p-10 rounded-2xl border-2 border-dashed transition-all cursor-pointer flex flex-col items-center justify-center text-center space-y-3 ${
          isDragging
            ? 'border-cyan-400 bg-cyan-950/20'
            : file
            ? 'border-cyan-500/40 bg-gray-900/60'
            : 'border-gray-800 bg-[#111827] hover:border-gray-700'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".csv"
          onChange={handleFileChange}
          className="hidden"
        />

        <div className="p-3.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
          <UploadCloud className="w-8 h-8" />
        </div>

        <div>
          {file ? (
            <div className="space-y-1">
              <p className="text-sm font-semibold text-white font-mono flex items-center justify-center space-x-1.5">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span>{file.name}</span>
              </p>
              <p className="text-xs text-gray-400 font-mono">
                {(file.size / 1024).toFixed(1)} KB — Ready to analyze
              </p>
            </div>
          ) : (
            <div className="space-y-1">
              <p className="text-sm font-medium text-gray-200">
                Drag and drop your network traffic CSV file here, or{' '}
                <span className="text-cyan-400 underline">browse</span>
              </p>
              <p className="text-xs text-gray-500 font-mono">
                Supports .csv files up to 5 MB (max 5,000 rows)
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <button
          type="button"
          onClick={handleLoadSample}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-xs text-gray-400 hover:text-gray-200 font-mono transition"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Load Pre-built Sample Dataset</span>
        </button>

        <button
          type="button"
          onClick={handleUpload}
          disabled={!file || isUploading}
          className="flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-lg shadow-cyan-950 transition disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {isUploading ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin" />
              <span>Analyzing & Ingesting Dataset...</span>
            </>
          ) : (
            <>
              <UploadCloud className="w-4 h-4" />
              <span>Start Ingestion & Analysis</span>
            </>
          )}
        </button>
      </div>

      {/* Error Message */}
      {errorMessage && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2 font-mono">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Upload Results Summary Card */}
      {result && (
        <div className="p-5 rounded-xl bg-emerald-950/30 border border-emerald-500/40 space-y-4 font-mono">
          <div className="flex items-center space-x-2 text-emerald-400 font-semibold text-sm">
            <CheckCircle2 className="w-5 h-5" />
            <span>Dataset Ingested & Analyzed Successfully</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-gray-900/80 border border-gray-800">
              <span className="text-gray-500 block text-[10px] uppercase">Processed</span>
              <span className="text-white font-bold text-base">{result.rows_processed}</span>
            </div>
            <div className="p-3 rounded-lg bg-gray-900/80 border border-gray-800">
              <span className="text-emerald-500 block text-[10px] uppercase">Accepted</span>
              <span className="text-emerald-400 font-bold text-base">{result.rows_accepted}</span>
            </div>
            <div className="p-3 rounded-lg bg-gray-900/80 border border-gray-800">
              <span className="text-rose-500 block text-[10px] uppercase">Suspicious</span>
              <span className="text-rose-400 font-bold text-base">{result.suspicious_count}</span>
            </div>
            <div className="p-3 rounded-lg bg-gray-900/80 border border-gray-800">
              <span className="text-amber-500 block text-[10px] uppercase">Alerts Raised</span>
              <span className="text-amber-400 font-bold text-base">{result.alerts_generated}</span>
            </div>
          </div>

          {result.errors && result.errors.length > 0 && (
            <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/30 text-amber-300 text-xs space-y-1">
              <span className="font-bold">Row Warnings ({result.rows_rejected} rows skipped):</span>
              <ul className="list-disc list-inside text-[11px] text-amber-200/80 space-y-0.5">
                {result.errors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Required CSV Schema Reference Guide */}
      <div className="p-5 rounded-xl bg-[#111827] border border-gray-800 space-y-3">
        <div className="flex items-center space-x-2 text-white font-semibold text-xs font-mono">
          <Info className="w-4 h-4 text-cyan-400" />
          <span>Expected CSV Schema Reference</span>
        </div>
        <p className="text-xs text-gray-400">
          The ingestion engine validates incoming CSV files against these column specifications:
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-gray-900/60 text-gray-400 uppercase text-[10px] border-b border-gray-800">
              <tr>
                <th className="py-2 px-3">Column Name</th>
                <th className="py-2 px-3">Requirement</th>
                <th className="py-2 px-3">Description</th>
                <th className="py-2 px-3">Example</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60 text-gray-300">
              <tr>
                <td className="py-2 px-3 text-cyan-400 font-bold">source_ip</td>
                <td className="py-2 px-3 text-rose-400">Required</td>
                <td className="py-2 px-3 text-gray-400">Originating host IPv4 address</td>
                <td className="py-2 px-3 text-gray-400">192.168.1.105</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-cyan-400 font-bold">destination_ip</td>
                <td className="py-2 px-3 text-rose-400">Required</td>
                <td className="py-2 px-3 text-gray-400">Target host IPv4 address</td>
                <td className="py-2 px-3 text-gray-400">10.0.0.10</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-cyan-400 font-bold">destination_port</td>
                <td className="py-2 px-3 text-rose-400">Required</td>
                <td className="py-2 px-3 text-gray-400">Target service port (0 to 65535)</td>
                <td className="py-2 px-3 text-gray-400">443</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-cyan-400 font-bold">protocol</td>
                <td className="py-2 px-3 text-rose-400">Required</td>
                <td className="py-2 px-3 text-gray-400">Transport protocol: TCP, UDP, ICMP</td>
                <td className="py-2 px-3 text-gray-400">TCP</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-gray-300">packet_count</td>
                <td className="py-2 px-3 text-gray-500">Optional</td>
                <td className="py-2 px-3 text-gray-400">Total packet count (default: 1)</td>
                <td className="py-2 px-3 text-gray-400">45</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-gray-300">byte_count</td>
                <td className="py-2 px-3 text-gray-500">Optional</td>
                <td className="py-2 px-3 text-gray-400">Total bytes transferred (default: 64)</td>
                <td className="py-2 px-3 text-gray-400">28400</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-gray-300">duration</td>
                <td className="py-2 px-3 text-gray-500">Optional</td>
                <td className="py-2 px-3 text-gray-400">Session duration in seconds (default: 0.0)</td>
                <td className="py-2 px-3 text-gray-400">2.15</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
