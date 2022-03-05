using System;
using System.Collections.Generic;
using System.Xml.Serialization;

namespace JWTLibrary
{
    /// <summary>
    ///  This class is utilized for storing all the paths ignored by the JWT middleware
    /// </summary>
    public class JwtPath
    {
        public JwtPath()
        {

        }

        public JwtPath(string Path)
        {
            this.Path = Path;
        }

        public string? Path { get; set; }
    }

    /// <summary>
    /// This class is responsible for most of the file management utilized by the JWT Library
    /// </summary>
    public class JwtLibraryFileManagement
    {
        private static string middlewareIgnorePath = $"{DIRECTORY}/middlewarePaths.xml";
        private static string secretPath = $"{DIRECTORY}/JwtSecret.txt";
        private const string DIRECTORY = "JWTLibraryRelated";

        /// <summary>
        /// Function for intializing the directory
        /// </summary>
        private static void InitializeDirectory()
        {
            // create the directory if it does not exist
            if (!Directory.Exists(DIRECTORY)) Directory.CreateDirectory(DIRECTORY);
        }

        /// <summary>
        /// Function for initializing and reading the xml file responsible for containing the list of ignored paths by the JWT Middleware.
        /// </summary>
        /// <returns>List of JwtPaths containing all the paths ignored or null if there is an error.</returns>
        public static List<JwtPath>? InitializeMiddlewareList()
        {
            try
            {
                List<JwtPath>? jwtPaths = new List<JwtPath>();

                // initialize the Directory just in case it hasnt been.
                InitializeDirectory();

                // check to ensure the file exists, if not create it
                if (!File.Exists(middlewareIgnorePath))
                {
                    // First write something so that there is something to read ...  
                    jwtPaths = new List<JwtPath> { new JwtPath("/api/User/Login"), new JwtPath("/api/User/Register") };
                    var writer = new XmlSerializer(typeof(List<JwtPath>));
                    var wfile = new StreamWriter(middlewareIgnorePath);
                    writer.Serialize(wfile, jwtPaths);
                    wfile.Close();
                }

                // file exists read all values
                else
                {
                    // create our serializer
                    XmlSerializer reader = new XmlSerializer(typeof(List<JwtPath>));
                    // grab the file
                    StreamReader file = new StreamReader(middlewareIgnorePath);
                    // deserialize
                    jwtPaths = (List<JwtPath>?)reader.Deserialize(file);
                    // close the file safely
                    file.Close();
                }

                // return paths
                return jwtPaths;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Function for getting the JWT Secret .. This should be called after calling InitializeDirectory() function.
        /// </summary>
        /// <returns>returns string if there are no errors </returns>
        public static string? GetSecret()
        {
            try
            {
                string secret;
                // initialize the Directory just in case it hasnt been.
                InitializeDirectory();

                if (!File.Exists(secretPath))
                {
                    using (StreamWriter sw = File.CreateText(secretPath))
                    {
                        // set default text
                        Console.WriteLine("Creating JwtSecret.txt, HIGHLY RECOMMEND CHANGING SECRET VALUE!");
                        sw.WriteLine("SecretShouldBeChanged");

                        sw.Close();
                    }

                    secret = File.ReadAllText(secretPath);
                }

                else
                {
                    // read in the secret
                    secret = File.ReadAllText(secretPath);
                }

                if (secret == null) throw new Exception("Secret is null please give it a value!");

                return secret;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }
    }
}
