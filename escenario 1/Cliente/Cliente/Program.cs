using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

class Client
{
    static void Main()
    {
        try
        {
          
            // Se inicializa el cliente
            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[1];
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);

            Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            sender.Connect(remoteEP);

            //se solicita la llave al servidor para cifrar el mensaje
            Console.WriteLine("Conectado al servidor. Recibiendo llave...");
            sender.Send(Encoding.ASCII.GetBytes("dame la llave"));
            // Recibir llave
            byte[] buffer2 = new byte[1024];
            int bytesRec2 = sender.Receive(buffer2);
            var llaveult = Encoding.ASCII.GetString(buffer2, 0, bytesRec2);
            // Clave secreta de 32 bytes para Salsa20
            byte[] key = Encoding.ASCII.GetBytes(llaveult); // 32 bytes key
            byte[] nonce = Encoding.ASCII.GetBytes("12345678"); // 8 bytes nonce

            // Mensaje original
            Console.WriteLine("Por favor, ingrese su mensaje:");

            while (true)
            {
                // Leer lo que el usuario escribe y guardarlo en una variable
                // Mensaje original
                Console.WriteLine("Por favor, ingrese su mensaje:");
                string mensajerec = Console.ReadLine();
                string message = mensajerec;
                byte[] messageBytes = Encoding.ASCII.GetBytes(message);

                // Cifrar con Salsa20
                byte[] encryptedMessage = EncryptSalsa20(messageBytes, key, nonce);

                Console.WriteLine("Conectado al servidor. Enviando mensaje cifrado...");

                // Enviar el mensaje cifrado
                sender.Send(encryptedMessage);

                // Recibir respuesta del servidor
                byte[] buffer = new byte[1024];
                int bytesRec = sender.Receive(buffer);
                Console.WriteLine("Respuesta del servidor: {0}", Encoding.ASCII.GetString(buffer, 0, bytesRec));

            }
          
        }
        catch (Exception e)
        {
            Console.WriteLine(e.ToString());
        }
    }

    //Funcion para cifrar usando Salsa20,usamos la biblioteca BouncyCastle en c#
    public static byte[] EncryptSalsa20(byte[] plainText, byte[] key, byte[] nonce)
    {
        Salsa20Engine engine = new Salsa20Engine(); // Salsa20
        ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), nonce);

        engine.Init(true, parameters); // true para cifrar
        byte[] cipherText = new byte[plainText.Length];
        engine.ProcessBytes(plainText, 0, plainText.Length, cipherText, 0);

        return cipherText;
    }
}
