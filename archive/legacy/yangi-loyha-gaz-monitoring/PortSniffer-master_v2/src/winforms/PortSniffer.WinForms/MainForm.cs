using System;
using System.Diagnostics;
using System.IO;
using System.IO.Ports;
using System.Text;
using System.Windows.Forms;

namespace PortSniffer.WinForms
{
    public partial class MainForm : Form
    {
        private Process _proc;

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
            // Load existing config
            try
            {
                var cfg = GetConfigPath();
                if (File.Exists(cfg))
                {
                    foreach (var line in File.ReadAllLines(cfg))
                    {
                        var t = line.Trim();
                        if (t.StartsWith("forward_url=", StringComparison.OrdinalIgnoreCase))
                        {
                            txtApi.Text = t.Substring("forward_url=".Length).Trim();
                        }
                    }
                }
            }
            catch { }

            // List COM ports
            cmbPort.Items.Clear();
            foreach (var port in SerialPort.GetPortNames())
            {
                cmbPort.Items.Add(port);
            }
            if (cmbPort.Items.Count > 0)
            {
                cmbPort.SelectedIndex = 0;
            }
        }

        private void btnSave_Click(object sender, EventArgs e)
        {
            try
            {
                File.WriteAllText(GetConfigPath(), "forward_url=" + txtApi.Text.Trim(), Encoding.UTF8);
                MessageBox.Show(this, "Saved.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            if (_proc != null)
            {
                MessageBox.Show(this, "Already running.", "Info");
                return;
            }

            if (cmbPort.SelectedItem == null)
            {
                MessageBox.Show(this, "Select a port.", "Info");
                return;
            }

            var port = cmbPort.SelectedItem.ToString();
            var types = string.IsNullOrWhiteSpace(txtTypes.Text) ? "RW" : txtTypes.Text.Trim().ToUpperInvariant();
            var url = txtApi.Text.Trim();

            var toolPath = Path.Combine(GetToolDirectory(), "PortSniffer-Tool.exe");
            if (!File.Exists(toolPath))
            {
                MessageBox.Show(this, "PortSniffer-Tool.exe not found next to the app.", "Error");
                return;
            }

            var psi = new ProcessStartInfo(toolPath)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                Arguments = string.IsNullOrEmpty(url)
                    ? $"/monitor {port} {types}"
                    : $"/monitor {port} {types} /forward {url}"
            };

            _proc = new Process();
            _proc.StartInfo = psi;
            _proc.OutputDataReceived += (s, a) => { if (a.Data != null) AppendLog(a.Data); };
            _proc.ErrorDataReceived += (s, a) => { if (a.Data != null) AppendLog(a.Data); };

            try
            {
                _proc.Start();
                _proc.BeginOutputReadLine();
                _proc.BeginErrorReadLine();
                AppendLog("Monitoring started.");
            }
            catch (Exception ex)
            {
                AppendLog("Error: " + ex.Message);
                _proc = null;
            }
        }

        private void btnStop_Click(object sender, EventArgs e)
        {
            try
            {
                if (_proc != null && !_proc.HasExited)
                {
                    _proc.Kill();
                }
            }
            catch { }
            finally
            {
                _proc = null;
                AppendLog("Monitoring stopped.");
            }
        }

        private void AppendLog(string line)
        {
            if (InvokeRequired) { BeginInvoke(new Action<string>(AppendLog), line); return; }
            txtLog.AppendText(line + Environment.NewLine);
        }
    }
}


