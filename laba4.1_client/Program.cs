using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

class Client
{
    private static readonly object consoleLock = new object(); // Лок для синхронізації доступу до консолі
    private static bool isWritingMessage = false; // Флаг, чи клієнт пише повідомлення
    private static bool isChatActive = true; // Флаг активності чату

    // Головна програм
    static async Task Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.InputEncoding = System.Text.Encoding.UTF8;
        try
        {
            Console.WriteLine("Впишіть ІР-аддресу серверу");
        string serverIp = Console.ReadLine();
        int port = 5000;
        if (!System.Net.IPAddress.TryParse(serverIp, out _))
        {
                throw new ArgumentException("Некоректний формат ІР-адреси");
        }
            using (TcpClient client = new TcpClient(serverIp, port)) // Підключення до сервера
            using (var sslStream = new SslStream(client.GetStream(), false, ValidateServerCertificate)) // SSL з'єднання
            {
                // Завантаження клієнтського сертифіката
                var clientCertificate = new X509Certificate2("client.pfx", "BestPassword");
                var certCollection = new X509CertificateCollection { clientCertificate };

                // Встановлення SSL з'єднання 
                await sslStream.AuthenticateAsClientAsync(
                    targetHost: serverIp,
                    clientCertificates: certCollection,
                    enabledSslProtocols: SslProtocols.Tls12,
                    checkCertificateRevocation: true);

                Console.WriteLine("З'єднання встановлено.");
                Console.WriteLine("Чат активний. Для заверешення чату закрийте програму або використайте комбінацію Ctrl+C не виділяючи текст");

                var reader = new StreamReader(sslStream);
                var writer = new StreamWriter(sslStream) { AutoFlush = true };

                // Потік для читання повідомлень від сервера
                _ = Task.Run(async () =>
                {
                    try
                    {
                        string message;
                        while (isChatActive && (message = await reader.ReadLineAsync()) != null)
                        {
                            lock (consoleLock)
                            {
                                ClearCurrentLine();
                                Console.WriteLine($"Сервер: {message}");
                                if (isWritingMessage)
                                {
                                    Console.Write("Ви: ");
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"З'єднання завершено: {ex.Message}");
                    }
                });

                // Відправлення повідомлень
                while (isChatActive)
                {
                    lock (consoleLock)
                    {
                        isWritingMessage = true; // Позначка, що клієнт пише повідомлення
                        Console.Write("Ви: ");
                    }

                    string clientMessage = Console.ReadLine(); // Читання повідомлення 
                    isWritingMessage = false;

                    if (isChatActive && !string.IsNullOrEmpty(clientMessage))
                    {
                        await writer.WriteLineAsync(clientMessage); // Відправка повідомлення серверу
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Помилка: {ex.Message}");
        }
    }

    // Перевірка сертифіката сервера через відбиток
    static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
    {
        // Очікуваний відбиток
        string expectedFingerprint = "72:3D:04:EC:93:71:F7:5D:17:97:92:07:DE:74:49:AA:C4:DF:6D:30:C5:14:EA:75:B1:2C:17:45:0E:1E:48:25";

        // Обчислення фактичного відбитку сертифіката сервера
        using (var hashAlgorithm = System.Security.Cryptography.SHA256.Create())
        {
            byte[] certHash = hashAlgorithm.ComputeHash(certificate.GetRawCertData());
            string actualFingerprint = BitConverter.ToString(certHash).Replace("-", ":");

            // Перевірка на відповідність
            if (actualFingerprint.Equals(expectedFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Сертифікат сервера успішно верифіковано.");
                return true;
            }
            else
            {
                Console.WriteLine("Помилка. Сертифікат сервера не підтверджений.");
                return false;
            }
        }
    }

    // Очистка поточного рядку в консолі
    static void ClearCurrentLine()
    {
        Console.SetCursorPosition(0, Console.CursorTop);
        Console.Write(new string(' ', Console.WindowWidth));
        Console.SetCursorPosition(0, Console.CursorTop);
    }
}