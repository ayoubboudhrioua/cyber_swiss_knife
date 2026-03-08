"""
Steganography Detector — analyzes images for hidden data using:
  - LSB (Least Significant Bit) analysis
  - Chi-square statistical test
  - File size anomaly detection
  - Metadata anomaly detection
No external image libs required beyond stdlib — uses raw bytes.
"""

import math
import os
import struct
import zlib
from pathlib import Path
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class SteganographyDetector:

    def analyze(self, file_path: str) -> dict:
        """Main entry — detect file type and run appropriate analysis."""
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {file_path}"}

        result = {
            "file": file_path,
            "size_bytes": path.stat().st_size,
            "extension": path.suffix.lower(),
            "findings": [],
            "risk_score": 0,
            "tests_run": [],
        }

        data = path.read_bytes()
        file_type = self._detect_type(data)
        result["detected_type"] = file_type

        if file_type == "PNG":
            self._analyze_png(data, result)
        elif file_type == "JPEG":
            self._analyze_jpeg(data, result)
        elif file_type == "BMP":
            self._analyze_bmp(data, result)
        else:
            result["findings"].append(
                f"File type '{file_type}' — running generic byte analysis"
            )

        # Run on all types
        self._lsb_analysis(data, result)
        self._entropy_analysis(data, result)
        self._appended_data_check(data, file_type, result)

        result["risk_score"] = min(result["risk_score"], 100)
        return result

    def _detect_type(self, data: bytes) -> str:
        if data[:8] == b'\x89PNG\r\n\x1a\n':
            return "PNG"
        elif data[:2] == b'\xff\xd8':
            return "JPEG"
        elif data[:2] == b'BM':
            return "BMP"
        elif data[:4] == b'GIF8':
            return "GIF"
        return "UNKNOWN"

    def _analyze_png(self, data: bytes, result: dict):
        """Check PNG chunks for anomalies."""
        result["tests_run"].append("PNG chunk analysis")
        try:
            i = 8  # skip PNG signature
            chunks = []
            while i < len(data) - 12:
                length = struct.unpack(">I", data[i:i+4])[0]
                chunk_type = data[i+4:i+8].decode("latin-1")
                chunks.append((chunk_type, length))
                i += 12 + length

            chunk_types = [c[0] for c in chunks]
            standard = {"IHDR", "IDAT", "IEND", "tEXt", "zTXt",
                        "iTXt", "cHRM", "gAMA", "sRGB", "bKGD",
                        "pHYs", "tIME"}
            unusual = [c for c in chunk_types if c not in standard]
            if unusual:
                result["findings"].append(f"Unusual PNG chunks found: {unusual} — possible hidden data containers")
                result["risk_score"] += 30

            # Multiple IDAT chunks can hide data
            idat_count = chunk_types.count("IDAT")
            if idat_count > 3:
                result["findings"].append(f"High IDAT chunk count ({idat_count}) — may indicate injected data")
                result["risk_score"] += 15

            result["png_chunks"] = chunk_types
        except Exception as e:
            result["findings"].append(f"PNG parse error: {e}")

    def _analyze_jpeg(self, data: bytes, result: dict):
        """Check JPEG for appended data after EOI marker."""
        result["tests_run"].append("JPEG marker analysis")
        eoi = data.rfind(b'\xff\xd9')
        if eoi != -1 and eoi < len(data) - 2:
            trailing = len(data) - eoi - 2
            result["findings"].append(
                f"Data appended after JPEG EOI marker: {trailing} bytes — strong indicator of hidden content"
            )
            result["risk_score"] += 50

    def _analyze_bmp(self, data: bytes, result: dict):
        """Check BMP header vs actual file size."""
        result["tests_run"].append("BMP header validation")
        try:
            declared_size = struct.unpack("<I", data[2:6])[0]
            actual_size = len(data)
            if abs(declared_size - actual_size) > 100:
                result["findings"].append(
                    f"BMP size mismatch: header says {declared_size}B, actual {actual_size}B"
                )
                result["risk_score"] += 25
        except Exception:
            pass

    def _lsb_analysis(self, data: bytes, result: dict):
        """
        Chi-square test on LSBs of pixel bytes.
        Natural images have non-uniform LSB distribution.
        LSB steganography makes it uniform (chi² drops).
        """
        result["tests_run"].append("LSB chi-square test")

        # Sample the middle chunk to avoid headers
        start = min(1024, len(data) // 4)
        sample = data[start: start + min(8192, len(data) // 2)]
        if len(sample) < 256:
            return

        lsb_counts = Counter(b & 1 for b in sample)
        zeros = lsb_counts[0]
        ones = lsb_counts[1]
        total = zeros + ones
        expected = total / 2

        # Chi-square statistic
        chi2 = ((zeros - expected) ** 2 + (ones - expected) ** 2) / expected

        result["lsb_chi2"] = round(chi2, 4)
        result["lsb_zero_pct"] = round(zeros / total * 100, 1)
        result["lsb_one_pct"] = round(ones / total * 100, 1)

        # Very low chi2 → suspiciously uniform → likely stego
        if chi2 < 0.5:
            result["findings"].append(
                f"LSB distribution suspiciously uniform (χ²={chi2:.3f}) — "
                "strong indicator of LSB steganography"
            )
            result["risk_score"] += 40
        elif chi2 < 2.0:
            result["findings"].append(
                f"LSB distribution slightly uniform (χ²={chi2:.3f}) — worth investigating"
            )
            result["risk_score"] += 15

    def _entropy_analysis(self, data: bytes, result: dict):
        """High entropy in image = compressed/encrypted hidden data."""
        result["tests_run"].append("Byte entropy analysis")

        counts = Counter(data)
        total = len(data)
        entropy = -sum(
            (c / total) * math.log2(c / total)
            for c in counts.values() if c > 0
        )
        result["entropy"] = round(entropy, 4)

        if entropy > 7.9:
            result["findings"].append(
                f"Extremely high entropy ({entropy:.3f}/8.0 bits/byte) — "
                "may contain encrypted or compressed hidden data"
            )
            result["risk_score"] += 20

    def _appended_data_check(self, data: bytes, file_type: str, result: dict):
        """Check for data appended after the logical end of file."""
        result["tests_run"].append("Appended data check")
        # Already handled for JPEG — skip
        if file_type == "JPEG":
            return

        # For PNG, check after IEND
        if file_type == "PNG":
            iend = data.rfind(b'IEND')
            if iend != -1:
                after_iend = len(data) - (iend + 8)
                if after_iend > 0:
                    result["findings"].append(
                        f"{after_iend} bytes found after PNG IEND chunk — hidden data likely present"
                    )
                    result["risk_score"] += 45

    def display_results(self, result: dict):
        if "error" in result:
            console.print(Panel(f"[red]❌ {result['error']}[/red]", border_style="red"))
            return

        score = result["risk_score"]
        if score == 0:
            verdict = "[green]CLEAN — No steganography indicators[/green] ✅"
            border = "green"
        elif score < 30:
            verdict = "[yellow]SUSPICIOUS — Some anomalies detected[/yellow] ⚠️"
            border = "yellow"
        else:
            verdict = "[red]HIGH RISK — Likely contains hidden data[/red] 🚨"
            border = "red"

        console.print(Panel(
            f"[bold]File:[/bold] {result['file']}\n"
            f"[bold]Type:[/bold] {result.get('detected_type', 'Unknown')}   "
            f"[bold]Size:[/bold] {result['size_bytes']:,} bytes   "
            f"[bold]Entropy:[/bold] {result.get('entropy', 'N/A')} bits/byte\n\n"
            f"[bold]Verdict:[/bold] {verdict}\n"
            f"[bold]Risk Score:[/bold] {score}/100",
            title="[bold cyan]🔍 Steganography Analysis[/bold cyan]",
            border_style=border
        ))

        if result.get("lsb_chi2") is not None:
            console.print(
                f"\n[dim]LSB χ² statistic: {result['lsb_chi2']}  "
                f"(0% ones: {result['lsb_zero_pct']}%  |  "
                f"1% ones: {result['lsb_one_pct']}%)[/dim]"
            )

        if result["findings"]:
            console.print("\n[bold red]🔎 Findings:[/bold red]")
            for i, finding in enumerate(result["findings"], 1):
                console.print(f"  {i}. {finding}")
        else:
            console.print("\n[green]No anomalies detected across all tests.[/green]")

        console.print(f"\n[dim]Tests run: {', '.join(result['tests_run'])}[/dim]")