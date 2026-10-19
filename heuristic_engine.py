import os
import math
import pefile


class HeuristicScanner:

    def __init__(self):

        self.suspicious_apis = [
            b'VirtualAlloc',
            b'VirtualProtect',
            b'WriteProcessMemory',
            b'CreateRemoteThread',
            b'SetWindowsHookEx',
            b'URLDownloadToFile',
            b'IsDebuggerPresent',
            b'RegSetValueEx'
        ]

        self.suspicious_sections = [
            b'.UPX',
            b'.aspack',
            b'.packer',
            b'.vmp'
        ]

    # ------------------------------------------------
    # ENTROPY CALCULATION
    # ------------------------------------------------

    def calculate_entropy(self, data):

        if not data:
            return 0

        entropy = 0

        for x in range(256):

            p_x = float(data.count(x)) / len(data)

            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)

        return entropy

    # ------------------------------------------------
    # FILE SCAN
    # ------------------------------------------------

    def scan_file(self, filepath):

        if not os.path.exists(filepath):
            return {"error": "File does not exist"}

        score = 0
        details = []

        # ------------------------------
        # CHECK IF FILE IS PE EXECUTABLE
        # ------------------------------

        try:
            pe = pefile.PE(filepath)
            is_pe = True

        except pefile.PEFormatError:
            is_pe = False

        except Exception as e:
            return {"error": str(e)}

        # ------------------------------
        # NON-PE FILES
        # ------------------------------

        if not is_pe:

            filesize = os.path.getsize(filepath)

            if filesize > 50 * 1024 * 1024:
                score += 10
                details.append("Very large file")

            return {
                "score": score,
                "details": details,
                "status": "Clean"
            }

        # ------------------------------
        # PE SECTION ANALYSIS
        # ------------------------------

        for section in pe.sections:

            sec_name = section.Name.strip(b'\x00')

            if any(sus_sec in sec_name for sus_sec in self.suspicious_sections):

                score += 25
                details.append(
                    f"Suspicious section: {sec_name.decode('utf-8','ignore')}"
                )

            entropy = self.calculate_entropy(section.get_data())

            if entropy > 7.0:

                score += 20
                details.append(
                    f"High entropy ({entropy:.2f}) in section {sec_name.decode('utf-8','ignore')}"
                )

        # ------------------------------
        # IMPORTED API CHECK
        # ------------------------------

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):

            for entry in pe.DIRECTORY_ENTRY_IMPORT:

                for imp in entry.imports:

                    if imp.name:

                        if any(api in imp.name for api in self.suspicious_apis):

                            score += 15

                            details.append(
                                f"Suspicious API: {imp.name.decode('utf-8','ignore')}"
                            )

        # ------------------------------
        # FINAL SCORE
        # ------------------------------

        final_score = min(score, 100)

        if final_score >= 60:
            status = "High-Risk Indicators"

        elif final_score >= 30:
            status = "Potential Risk Patterns"

        else:
            status = "Standard Patterns"

        return {
            "score": final_score,
            "details": details,
            "status": status
        }
