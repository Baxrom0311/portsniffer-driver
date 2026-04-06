using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Ports;
using System.Text;
using System.Windows.Forms;

namespace PortSniffer.WinForms
{
    public partial class MainForm : Form
    {
        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);
        private Process _proc;
        private bool _suppressExitLog;

        public MainForm()
        {
            InitializeComponent();
        }

        private string GetToolDirectory()
        {
            // Assume the CLI tool resides next to the WinForms exe in a sibling or the same tree; allow user to copy both into one folder
            return AppDomain.CurrentDomain.BaseDirectory;
        }

        private string GetConfigPath()
        {
            return Path.Combine(GetToolDirectory(), "PortSniffer-Tool.config");
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            LoadSavedApiUrl();
            LoadAvailablePorts();
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            StopMonitorProcess(true, false);
        }

        private void btnSave_Click(object sender, EventArgs e)
        {
            try
            {
                File.WriteAllText(GetConfigPath(), "forward_url=" + txtApi.Text.Trim(), Utf8NoBom);
                MessageBox.Show(this, "Saved.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            string types;
            string toolPath;
            string arguments;
            var ports = ParsePortsInput(cmbPort.Text);

            if (IsMonitorRunning())
            {
                MessageBox.Show(this, "Already running.", "Info");
                return;
            }

            if (ports.Count == 0)
            {
                MessageBox.Show(this, "Enter one or more ports. Use space or comma as separator.", "Info");
                return;
            }

            types = NormalizeTypes(txtTypes.Text);
            if (types == null)
            {
                MessageBox.Show(this, "Types must contain only R, W, or C.", "Error");
                return;
            }

            toolPath = Path.Combine(GetToolDirectory(), "PortSniffer-Tool.exe");
            if (!File.Exists(toolPath))
            {
                MessageBox.Show(this, "PortSniffer-Tool.exe not found next to the app.", "Error");
                return;
            }

            arguments = BuildMonitorArguments(ports, types, txtApi.Text.Trim());
            StartMonitorProcess(toolPath, arguments);
        }

        private void btnStop_Click(object sender, EventArgs e)
        {
            StopMonitorProcess(true, true);
        }

        private void LoadSavedApiUrl()
        {
            try
            {
                var cfg = GetConfigPath();
                if (!File.Exists(cfg))
                {
                    return;
                }

                foreach (var line in File.ReadAllLines(cfg))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("forward_url=", StringComparison.OrdinalIgnoreCase))
                    {
                        txtApi.Text = trimmed.Substring("forward_url=".Length).Trim();
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                AppendLog("Config load error: " + ex.Message);
            }
        }

        private void LoadAvailablePorts()
        {
            var previouslySelected = cmbPort.Text;

            cmbPort.Items.Clear();
            foreach (var port in SerialPort.GetPortNames())
            {
                cmbPort.Items.Add(port);
            }

            if (!string.IsNullOrWhiteSpace(previouslySelected))
            {
                cmbPort.Text = previouslySelected;
            }
            else if (cmbPort.Items.Count > 0)
            {
                cmbPort.Text = cmbPort.Items[0].ToString();
            }
        }

        private static string NormalizeTypes(string value)
        {
            var result = new StringBuilder(3);
            var seen = new HashSet<char>();
            var input = string.IsNullOrWhiteSpace(value) ? "RW" : value.Trim().ToUpperInvariant();

            foreach (var ch in input)
            {
                if (char.IsWhiteSpace(ch))
                {
                    continue;
                }

                if (ch != 'R' && ch != 'W' && ch != 'C')
                {
                    return null;
                }

                if (seen.Add(ch))
                {
                    result.Append(ch);
                }
            }

            return result.Length == 0 ? null : result.ToString();
        }

        private static List<string> ParsePortsInput(string value)
        {
            var ports = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var tokens = (value ?? string.Empty).Split(new[] { ' ', '\t', '\r', '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var token in tokens)
            {
                var port = token.Trim();
                if (port.Length == 0)
                {
                    continue;
                }

                if (seen.Add(port))
                {
                    ports.Add(port);
                }
            }

            return ports;
        }

        private static string BuildMonitorArguments(IList<string> ports, string types, string url)
        {
            var builder = new StringBuilder("/monitor");

            foreach (var port in ports)
            {
                builder.Append(' ');
                builder.Append(QuoteArgument(port));
            }

            builder.Append(' ');
            builder.Append(types);

            if (!string.IsNullOrWhiteSpace(url))
            {
                builder.Append(" /forward ");
                builder.Append(QuoteArgument(url.Trim()));
            }

            return builder.ToString();
        }

        private static string QuoteArgument(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private bool IsMonitorRunning()
        {
            return _proc != null && !_proc.HasExited;
        }

        private void StartMonitorProcess(string toolPath, string arguments)
        {
            var psi = new ProcessStartInfo(toolPath)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                Arguments = arguments
            };

            _suppressExitLog = false;
            _proc = new Process();
            _proc.StartInfo = psi;
            _proc.EnableRaisingEvents = true;
            _proc.Exited += OnMonitorExited;
            _proc.OutputDataReceived += OnMonitorDataReceived;
            _proc.ErrorDataReceived += OnMonitorDataReceived;

            try
            {
                _proc.Start();
                _proc.BeginOutputReadLine();
                _proc.BeginErrorReadLine();
                AppendLog("Monitoring started.");
            }
            catch (Exception ex)
            {
                AppendLog("Start error: " + ex.Message);
                CleanupProcess();
            }
        }

        private void StopMonitorProcess(bool suppressExitLog, bool logMessage)
        {
            if (_proc == null)
            {
                return;
            }

            _suppressExitLog = suppressExitLog;

            try
            {
                if (!_proc.HasExited)
                {
                    if (logMessage)
                    {
                        AppendLog("Stopping monitor process...");
                    }

                    _proc.Kill();
                    _proc.WaitForExit(2000);
                }
            }
            catch (Exception ex)
            {
                if (logMessage)
                {
                    AppendLog("Stop error: " + ex.Message);
                }
            }
            finally
            {
                CleanupProcess();
                if (logMessage)
                {
                    AppendLog("Monitoring stopped.");
                }
            }
        }

        private void OnMonitorDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                AppendLog(e.Data);
            }
        }

        private void OnMonitorExited(object sender, EventArgs e)
        {
            var proc = sender as Process;
            var shouldLog = !_suppressExitLog;
            var exitCode = 0;

            if (proc == null)
            {
                return;
            }

            try
            {
                exitCode = proc.ExitCode;
            }
            catch
            {
            }

            if (InvokeRequired)
            {
                BeginInvoke(new Action<object, EventArgs>(OnMonitorExited), sender, e);
                return;
            }

            if (ReferenceEquals(_proc, proc))
            {
                CleanupProcess();
                if (shouldLog)
                {
                    AppendLog("Monitoring process exited with code " + exitCode + ".");
                }
            }
            else
            {
                proc.Dispose();
            }

            _suppressExitLog = false;
        }

        private void CleanupProcess()
        {
            var proc = _proc;
            _proc = null;

            if (proc != null)
            {
                proc.Exited -= OnMonitorExited;
                proc.OutputDataReceived -= OnMonitorDataReceived;
                proc.ErrorDataReceived -= OnMonitorDataReceived;
                proc.Dispose();
            }
        }

        private void AppendLog(string line)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action<string>(AppendLog), line);
                return;
            }

            txtLog.AppendText(line + Environment.NewLine);
        }
    }
}
