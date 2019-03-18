/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
namespace org.webpki.sks.ws.client
{
    using System.Security.Cryptography;
    using System.Windows.Forms;
    using System.Reflection;
    using System.IO;
    using System.Collections.Generic;
    using org.webpki.sks.ws.client.BouncyCastle.Utilities.Encoders;

    internal class SKSAuthorizationDialog : Form
    {
        private System.ComponentModel.IContainer components = null;

        private Button authorization_Cancel_Button;
        private Button authorization_OK_Button;
        private TextBox authorization_TextBox;
        private ToolTip authorization_ToolTip;
        private Label retry_warning_Label;
        private PictureBox attention_PictureBox;
        private PictureBox key_info_PictureBox;
        
        internal string password;
        private int key_handle;
        private bool retry_warning;
        private bool show_picture;
        private string picture_resource;
        private string picture_tooltip_text;
        private int retriesleft;
        private PassphraseFormat pin_format;
        private string add_on_dialog_header = "";
 
        internal SKSAuthorizationDialog(int key_handle,
                                        PassphraseFormat format,
                                        Grouping grouping,
                                        AppUsage app_usage,
                                        int zero_or_retriesleft)
        {
        	this.key_handle = key_handle;
            this.retry_warning = zero_or_retriesleft != 0;
            this.retriesleft = zero_or_retriesleft;
            this.pin_format = format;
            if (app_usage == AppUsage.SIGNATURE &&
                (grouping == Grouping.UNIQUE || grouping == Grouping.SIGNATURE_PLUS_STANDARD))
            {
            	show_picture = true;
            	add_on_dialog_header = " - SIGNATURE";
            	picture_resource = "sks.signsymb.gif";
            	picture_tooltip_text = "Signature operation requiring a specific PIN"; 
            } 
            if (app_usage == AppUsage.AUTHENTICATION && grouping == Grouping.UNIQUE)
            {
            	show_picture = true;
            	add_on_dialog_header = " - AUTHENTICATION";
            	picture_resource = "sks.idcard.gif";
            	picture_tooltip_text = "Authentication operation requiring a specific PIN"; 
            } 
            if (app_usage == AppUsage.ENCRYPTION && grouping == Grouping.UNIQUE)
            {
            	show_picture = true;
            	add_on_dialog_header = " - ENCRYPTION";
            	picture_resource = "sks.encrypt.gif";
            	picture_tooltip_text = "Encryption operation requiring a specific PIN"; 
            } 
            pin_format = format;
            InitializeComponent();
        }

        private void authorization_OK_Button_Click(object sender, System.EventArgs e)
        {
            password = authorization_TextBox.Text;
            if (pin_format == PassphraseFormat.BINARY)
            {
            	if (!System.Text.RegularExpressions.Regex.IsMatch(password,"^([a-fA-F0-9][a-fA-F0-9])+$"))
            	{
            		password = "";
            	}
            }
            else if (pin_format == PassphraseFormat.ALPHANUMERIC)
            {
            	password = password.ToUpper();
            }
            if (password.Length > 0)
            {
	            DialogResult = DialogResult.OK;
	            Close();
            }
            else
            {
                System.Media.SystemSounds.Exclamation.Play();
            }
        }

        private void key_info_PictureBox_Click(object sender, System.EventArgs e)
        {
            MessageBox.Show("Not yet implemented :-(",
                            "Key Information key #" + key_handle,
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Exclamation);
        }

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
            components = new System.ComponentModel.Container();
            
            authorization_ToolTip = new ToolTip(components);
            
            authorization_Cancel_Button = new Button();
            authorization_OK_Button = new Button();
            authorization_TextBox = new TextBox();
            key_info_PictureBox = new PictureBox();
            authorization_ToolTip.SetToolTip(authorization_TextBox, "The authorization PIN");
            authorization_ToolTip.SetToolTip(key_info_PictureBox, "Get more information about the key");
            if (show_picture)
            {
	            attention_PictureBox = new PictureBox();
                authorization_ToolTip.SetToolTip(attention_PictureBox, picture_tooltip_text);
	        }
            if (retry_warning)
            {
            	retry_warning_Label = new Label();
            }
            SuspendLayout();
            if (retry_warning)
            {
                retry_warning_Label.AutoSize = true;
                retry_warning_Label.Font =  new System.Drawing.Font(retry_warning_Label.Font, retry_warning_Label.Font.Style | System.Drawing.FontStyle.Bold);
                retry_warning_Label.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(192)))), ((int)(((byte)(0)))), ((int)(((byte)(0)))));
                retry_warning_Label.Location = new System.Drawing.Point(101, 13);
                retry_warning_Label.Name = "retry_warning_Label";
                retry_warning_Label.TabIndex = 3;
                retry_warning_Label.Text = "You have " + retriesleft + " retries left";
            }
            
            Assembly assembly = Assembly.GetExecutingAssembly();
            Stream image_stream = assembly.GetManifestResourceStream("sks.keyinfo.png");
            key_info_PictureBox.Image = new System.Drawing.Bitmap(image_stream);
            key_info_PictureBox.Name = "key_info_PictureBox";
            key_info_PictureBox.SizeMode = PictureBoxSizeMode.AutoSize;
            key_info_PictureBox.TabIndex = 6;
            key_info_PictureBox.TabStop = false;
            key_info_PictureBox.Click += new System.EventHandler(key_info_PictureBox_Click);
          
            // 
            // authorization_OK_Button
            //
            int lower_margin; 
            authorization_OK_Button.Location = new System.Drawing.Point(lower_margin = authorization_OK_Button.Size.Width / 3, 80);
            authorization_OK_Button.Name = "authorization_OK_Button";
            authorization_OK_Button.TabIndex = 1;
            authorization_OK_Button.Text = "OK";
            authorization_OK_Button.UseVisualStyleBackColor = true;
            authorization_OK_Button.Click += new System.EventHandler(authorization_OK_Button_Click);
			int total_width = authorization_OK_Button.Size.Width * 4;
            key_info_PictureBox.Location = new System.Drawing.Point(total_width - 5 - key_info_PictureBox.Width, 5);
            // 
            // authorization_Cancel_Button
            // 
            authorization_Cancel_Button.DialogResult = DialogResult.Cancel;
            authorization_Cancel_Button.Location = new System.Drawing.Point((authorization_OK_Button.Size.Width * 8) / 3, 80);
            authorization_Cancel_Button.Name = "authorization_Cancel_Button";
            authorization_Cancel_Button.TabIndex = 2;
            authorization_Cancel_Button.Text = "Cancel";
            authorization_Cancel_Button.UseVisualStyleBackColor = true;
            // 
            // authorization_TextBox
            //
            authorization_TextBox.Width = authorization_OK_Button.Size.Width * 2;
            authorization_TextBox.PasswordChar = '\u25CF';            
            authorization_TextBox.Location = new System.Drawing.Point((total_width - authorization_TextBox.Size.Width) / 2, 42);
            authorization_TextBox.Name = "authorization_TextBox";
            authorization_TextBox.TabIndex = 0;
			//
            if (show_picture)
            {
	            image_stream = assembly.GetManifestResourceStream(picture_resource);
	            attention_PictureBox.Image = new System.Drawing.Bitmap(image_stream);
	            attention_PictureBox.Name = "attention_PictureBox";
	            attention_PictureBox.SizeMode = PictureBoxSizeMode.AutoSize;
	            attention_PictureBox.TabIndex = 5;
	            attention_PictureBox.TabStop = false;
	            attention_PictureBox.Location = new System.Drawing.Point(authorization_TextBox.Left - 10 - attention_PictureBox.Width,
	                                                                     authorization_TextBox.Top + authorization_TextBox.Height - attention_PictureBox.Height);
	        }
            // 
            // SKSAuthorizationDialog
            // 
			CancelButton = authorization_Cancel_Button;
            AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new System.Drawing.Size(total_width, authorization_OK_Button.Size.Height + lower_margin + authorization_OK_Button.Top);
            MaximizeBox = false;
            MinimizeBox = false;
            Controls.Add(authorization_TextBox);
            Controls.Add(authorization_OK_Button);
            Controls.Add(authorization_Cancel_Button);
            Controls.Add(key_info_PictureBox);
            if (show_picture)
            {
	            Controls.Add(attention_PictureBox);
	        }
            if (retry_warning)
            {
	            Controls.Add(retry_warning_Label);
            }
            Name = "SKSAuthorizationDialog";
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            Text = "PIN Code" + add_on_dialog_header;
            TopMost = true;
            ResumeLayout(false);
            PerformLayout();
            
            if (retry_warning)
            {
            	System.Media.SystemSounds.Hand.Play();
            }
            
        }

    }

    public partial class SKSWSProxy
    {
        Dictionary<int, byte[]> pin_cache =  new Dictionary<int, byte[]>();  // key_handle, pin
        
        private string device_id;
        
        public string DeviceID
        {
            get { return device_id; }
            set { device_id = value; }
        } 
        
        private static byte[] SHARED_SECRET_32 = {0,1,2,3,4,5,6,7,8,9,1,0,3,2,5,4,7,6,9,8,9,8,7,6,5,4,3,2,1,0,3,2};
        
        private byte[] GetEncryptedAuthorization (byte[] authorization)
        {
            using (AesManaged aes = new AesManaged())
            {
                byte[] IV = new byte[16];
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                {
	            	rng.GetBytes(IV);
	            }
                aes.Key = SHARED_SECRET_32;
                aes.IV = IV;
                byte[] encrypted;
                using (MemoryStream total = new MemoryStream())
                {
                    using (MemoryStream ms_encrypt = new MemoryStream())
                    {
                        using (CryptoStream cs_encrypt = new CryptoStream(ms_encrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
 	                        cs_encrypt.Write(authorization, 0, authorization.Length);
 	                        cs_encrypt.FlushFinalBlock(); 
                    	}
                    	ms_encrypt.Flush();
    	                encrypted = ms_encrypt.ToArray();
                 	}
                 	total.Write (IV, 0, IV.Length);
                 	total.Write (encrypted, 0, encrypted.Length);
                 	encrypted = total.ToArray();
                 	total.SetLength(0);
                    using (HMACSHA256 hmac = new HMACSHA256(SHARED_SECRET_32))
				    {
				    	total.Write(hmac.ComputeHash(encrypted), 0, 32);
				    	total.Write(encrypted, 0, encrypted.Length);
				    }
				    return total.ToArray();
             	}
         	}
        }
        
        public void PerformTrustedGUIAuthorization (int key_handle, ref byte[] authorization, ref bool tga)
        {
            KeyProtectionInfo kpi = getKeyProtectionInfo(key_handle);
            if ((kpi.ProtectionStatus & KeyProtectionInfo.PROTSTAT_PIN_PROTECTED) != 0)
            {
                if (kpi.InputMethod == InputMethod.TRUSTED_GUI)
                {
                    if (authorization != null)
                    {
                        throw new System.ArgumentException ("Redundant \"Authorization\"");
                    }
                }
                else if (kpi.InputMethod == InputMethod.PROGRAMMATIC || authorization != null)
                {
					tga = false;
                    return;
                }
	            if ((kpi.ProtectionStatus & KeyProtectionInfo.PROTSTAT_PIN_BLOCKED) != 0)
	            {
	                MessageBox.Show("Key #" + key_handle + " is blocked due to previous PIN errors",
	                                "Authorization Error",
                                    MessageBoxButtons.OK,
                                    MessageBoxIcon.Exclamation);
	                throw new SKSException("Key locked, user message", SKSException.ERROR_USER_ABORT);
	            }
	            KeyAttributes ka = getKeyAttributes (key_handle);
	            if (kpi.EnablePinCaching)
	            {
	                if (tga)
	                {
						// Failed to authenticate - Clear cache
	                    pin_cache.Remove (key_handle);
	                }
	                else if (pin_cache.ContainsKey (key_handle))
	                {
	                    // First try and we do have a cache - Use it
	                    tga = true;
	                    authorization = GetEncryptedAuthorization (pin_cache[key_handle]);
	                    return;
	                }
	            }
                SKSAuthorizationDialog authorization_form = new SKSAuthorizationDialog(key_handle,
                                                                                       (PassphraseFormat)kpi.Format,
                                                                                       (Grouping)kpi.Grouping,
                                                                                       (AppUsage)ka.AppUsage,
                                                                                       kpi.PinErrorCount == 0 ? 0 : kpi.RetryLimit - kpi.PinErrorCount);
                if (authorization_form.ShowDialog() == DialogResult.OK)
                {
                	authorization = 
                	   ((PassphraseFormat)kpi.Format == PassphraseFormat.BINARY) ?
                	                                                Hex.Decode (authorization_form.password)
                	                                                             :
                	                                                System.Text.Encoding.UTF8.GetBytes(authorization_form.password);
    	            if (kpi.EnablePinCaching)
	                {
	                	// Although the authorization may be incorrect we will just be
	                	// prompted again so we can save it in the cache anyway
                    	pin_cache[key_handle] = authorization;
                    }
                    authorization = GetEncryptedAuthorization (authorization); 
					tga = true;
           		}
           		else
           		{
                    throw new SKSException("Canceled by user", SKSException.ERROR_USER_ABORT);
                }
           	}
           	else
           	{
                tga = false;
            }
         }
    }
}