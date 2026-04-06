namespace PortSniffer.WinForms
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.txtApi = new System.Windows.Forms.TextBox();
            this.btnSave = new System.Windows.Forms.Button();
            this.cmbPort = new System.Windows.Forms.ComboBox();
            this.txtTypes = new System.Windows.Forms.TextBox();
            this.btnStart = new System.Windows.Forms.Button();
            this.btnStop = new System.Windows.Forms.Button();
            this.txtLog = new System.Windows.Forms.TextBox();
            this.SuspendLayout();
            // 
            // txtApi
            // 
            this.txtApi.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtApi.Location = new System.Drawing.Point(12, 12);
            this.txtApi.Name = "txtApi";
            this.txtApi.Size = new System.Drawing.Size(536, 20);
            this.txtApi.TabIndex = 0;
            // 
            // btnSave
            // 
            this.btnSave.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnSave.Location = new System.Drawing.Point(554, 10);
            this.btnSave.Name = "btnSave";
            this.btnSave.Size = new System.Drawing.Size(75, 23);
            this.btnSave.TabIndex = 1;
            this.btnSave.Text = "Save URL";
            this.btnSave.UseVisualStyleBackColor = true;
            this.btnSave.Click += new System.EventHandler(this.btnSave_Click);
            // 
            // cmbPort
            // 
            this.cmbPort.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbPort.FormattingEnabled = true;
            this.cmbPort.Location = new System.Drawing.Point(12, 50);
            this.cmbPort.Name = "cmbPort";
            this.cmbPort.Size = new System.Drawing.Size(121, 21);
            this.cmbPort.TabIndex = 2;
            // 
            // txtTypes
            // 
            this.txtTypes.Location = new System.Drawing.Point(139, 51);
            this.txtTypes.Name = "txtTypes";
            this.txtTypes.Size = new System.Drawing.Size(68, 20);
            this.txtTypes.TabIndex = 3;
            this.txtTypes.Text = "RWC";
            // 
            // btnStart
            // 
            this.btnStart.Location = new System.Drawing.Point(225, 49);
            this.btnStart.Name = "btnStart";
            this.btnStart.Size = new System.Drawing.Size(89, 23);
            this.btnStart.TabIndex = 4;
            this.btnStart.Text = "Start";
            this.btnStart.UseVisualStyleBackColor = true;
            this.btnStart.Click += new System.EventHandler(this.btnStart_Click);
            // 
            // btnStop
            // 
            this.btnStop.Location = new System.Drawing.Point(320, 49);
            this.btnStop.Name = "btnStop";
            this.btnStop.Size = new System.Drawing.Size(89, 23);
            this.btnStop.TabIndex = 5;
            this.btnStop.Text = "Stop";
            this.btnStop.UseVisualStyleBackColor = true;
            this.btnStop.Click += new System.EventHandler(this.btnStop_Click);
            // 
            // txtLog
            // 
            this.txtLog.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtLog.Location = new System.Drawing.Point(12, 88);
            this.txtLog.Multiline = true;
            this.txtLog.Name = "txtLog";
            this.txtLog.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.txtLog.Size = new System.Drawing.Size(617, 350);
            this.txtLog.TabIndex = 6;
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(641, 450);
            this.Controls.Add(this.txtLog);
            this.Controls.Add(this.btnStop);
            this.Controls.Add(this.btnStart);
            this.Controls.Add(this.txtTypes);
            this.Controls.Add(this.cmbPort);
            this.Controls.Add(this.btnSave);
            this.Controls.Add(this.txtApi);
            this.Name = "MainForm";
            this.Text = "PortSniffer";
            this.Load += new System.EventHandler(this.MainForm_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        private System.Windows.Forms.TextBox txtApi;
        private System.Windows.Forms.Button btnSave;
        private System.Windows.Forms.ComboBox cmbPort;
        private System.Windows.Forms.TextBox txtTypes;
        private System.Windows.Forms.Button btnStart;
        private System.Windows.Forms.Button btnStop;
        private System.Windows.Forms.TextBox txtLog;
    }
}


