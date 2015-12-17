/* Interpreter for MetaGME models written by Lawrence Waller
 * Note: only works properly on GME models, not metamodels
 * 
 * The assignment was only to create a working model interpreter,
 * creating a metamodel interpreter with a properly indented hierarchy is much trickier.
 * 
 */
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using GME.CSharp;
using GME;
using GME.MGA;
using GME.MGA.Core;

using System.Collections;
using System.Xml;

namespace Miniproject2Interpreter
{
    /// <summary>
    /// This class implements the necessary COM interfaces for a GME interpreter component.
    /// </summary>
    [Guid(ComponentConfig.guid),
    ProgId(ComponentConfig.progID),
    ClassInterface(ClassInterfaceType.AutoDual)]
    [ComVisible(true)]
    public class Miniproject2InterpreterInterpreter : IMgaComponentEx, IGMEVersionInfo
    {
        /// <summary>
        /// Contains information about the GUI event that initiated the invocation.
        /// </summary>
        public enum ComponentStartMode
        {
            GME_MAIN_START = 0, 		// Not used by GME
            GME_BROWSER_START = 1,      // Right click in the GME Tree Browser window
            GME_CONTEXT_START = 2,		// Using the context menu by right clicking a model element in the GME modeling window
            GME_EMBEDDED_START = 3,		// Not used by GME
            GME_MENU_START = 16,		// Clicking on the toolbar icon, or using the main menu
            GME_BGCONTEXT_START = 18,	// Using the context menu by right clicking the background of the GME modeling window
            GME_ICON_START = 32,		// Not used by GME
            GME_SILENT_MODE = 128 		// Not used by GME, available to testers not using GME
        }

        /// <summary>
        /// This function is called for each interpreter invocation before Main.
        /// Don't perform MGA operations here unless you open a transaction.
        /// </summary>
        /// <param name="project">The handle of the project opened in GME, for which the interpreter was called.</param>
        public void Initialize(MgaProject project)
        {
            // TODO: Add your initialization code here...            
        }

        /// <summary>
        /// The main entry point of the interpreter. A transaction is already open,
        /// GMEConsole is available. A general try-catch block catches all the exceptions
        /// coming from this function, you don't need to add it. For more information, see InvokeEx.
        /// </summary>
        /// <param name="project">The handle of the project opened in GME, for which the interpreter was called.</param>
        /// <param name="currentobj">The model open in the active tab in GME. Its value is null if no model is open (no GME modeling windows open). </param>
        /// <param name="selectedobjs">
        /// A collection for the selected model elements. It is never null.
        /// If the interpreter is invoked by the context menu of the GME Tree Browser, then the selected items in the tree browser. Folders
        /// are never passed (they are not FCOs).
        /// If the interpreter is invoked by clicking on the toolbar icon or the context menu of the modeling window, then the selected items 
        /// in the active GME modeling window. If nothing is selected, the collection is empty (contains zero elements).
        /// </param>
        /// <param name="startMode">Contains information about the GUI event that initiated the invocation.</param>


        //I am aware this is not good style. I am sorry. Javascript is such a convenient lover considered to the Iron Lady that is the C family.
        int vulnerabilities = 0;
        public void incrementVulnerabilities(){
            vulnerabilities++;
        }
        
        [ComVisible(false)]
        public void Main(MgaProject project, MgaFCO currentobj, MgaFCOs selectedobjs, ComponentStartMode startMode)
        {
            IMgaFolder rootFolder = project.RootFolder;

            string modelResult = "LIKELY SECURE";
            int modelProblems = 0;

            System.Collections.ArrayList myOutput = new System.Collections.ArrayList();

            myOutput.Add(writeAtIndentLevel(0, "<html><body>"));
            myOutput.Add(writeAtIndentLevel(0, "<div style='background-color: gold'>")); //log intro
            myOutput.Add(writeAtIndentLevel(0, "<h1>Project KANDAR: A Framework for Assessing Threats to Industrial Processes</h1>")); 
            myOutput.Add(writeAtIndentLevel(0, "<h2>Lawrence Waller, 2015</h2>"));
            myOutput.Add(writeAtIndentLevel(0, "</div>"));
            myOutput.Add(writeAtIndentLevel(0, "<hr>"));

            myOutput.Add(writeAtIndentLevel(0, "<div style='background-color: grey'>")); //log intro
            myOutput.Add(writeAtIndentLevel(0, "<h2>MODEL STRUCTURE ANALYSIS: " + modelResult + ", " + modelProblems + " vulnerabilities." + "</h2>"));
            myOutput.Add(writeAtIndentLevel(0, "</div>"));

            //proj.Meta.GetType()
            myOutput.Add(writeAtIndentLevel(0, "<p>" + "List of Model Factories:" + "</p>")); //log root folder

            //everything in the root is an Industrial Model...
            foreach (var proj in project.RootFolder.ChildFCOs.Cast<MgaFCO>())
            {
                //process and then traverse it...
                myOutput.Add(writeAtIndentLevel(0, "<div style='border: solid; background-color:honeydew'>"));
                myOutput.Add(writeAtIndentLevel(0, "<p><b>" + proj.Name + "</b><i style='color:gray'>(Model of type " + proj.Meta.Name + ")</i></p>"));
                var temp = process(proj as MgaModel, 2); //process all the base level models
                foreach (string i in temp)
                {
                    myOutput.Add(writeAtIndentLevel(0, i));

                }
                myOutput.Add(writeAtIndentLevel(0, "</div>"));
                continue;
                
            }
            myOutput.Add(writeAtIndentLevel(0, "</body></html>"));
            if (vulnerabilities != 0)
            {
                myOutput.RemoveAt(7);
                myOutput.Insert(7, "<h2>MODEL STRUCTURE ANALYSIS: " + "NOT SECURE" + ", " + vulnerabilities + " vulnerability." + "</h2>"); //grammar stickler here
            }
            else if (vulnerabilities > 1)
            {
                myOutput.RemoveAt(7);
                myOutput.Insert(7, "<h2>MODEL STRUCTURE ANALYSIS: " + "NOT SECURE" + ", " + vulnerabilities + " vulnerabilities." + "</h2>");
            }
            writeToFile(myOutput, "VulnerabilityAssessment.html"); //send HTML to file in same directory as model	
		    
        }

        public static string XMLParser(string input)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load("C://Users/Lawrence/Desktop/MIC_FinalProject/official-cpe-dictionary_v2.3.xml");

            XmlNodeList titles = doc.GetElementsByTagName("title");
            XmlNodeList cpes = doc.GetElementsByTagName("cpe-item");

            int length = cpes.Count;

            for (int i = 0; i < length; i++)
            {
                XmlNode parent = cpes[i];
                if (parent.ChildNodes[0].InnerText == input)
                {
                    return parent.Attributes["name"].Value;
                }
            }
            return "";
        }

        public System.Collections.ArrayList processSoftware(MgaFCO proj, int indentLevel)
        {
            System.Collections.ArrayList myOutput = new System.Collections.ArrayList();

            //if the element is a model
            if (proj is MgaModel)
            {
                var whatIsThis = isSoftwareOrOS(proj as MgaModel);
                bool flag = true;
                if ((whatIsThis == "software") || (whatIsThis == "os")) //if the model is software or OS...
                {
                    foreach (MgaAttribute attr in (proj as MgaModel).Attributes)
                    {
                        if (flag && whatIsThis == "software")
                        {
                            flag = false;
                            continue;
                        }

                        var parseResult = XMLParser(attr.Value.ToString());
                        if (parseResult != "")//check in database, false if vulnerable, true if safe
                        {
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<div style='background-color:red; border: 5px solid; margin:5px; padding:5px; border-radius:5px'>" + proj.Name + "<i style='color: gray'> (Model of type " + proj.Meta.Name + ")</i><br>"));
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<i style='color: white'>" + "UNSAFE: SOFTWARE FLAGGED BY NIST DATABASE" + "</i>"));
                            incrementVulnerabilities();

                            foreach (var elem in (proj as MgaModel).ChildFCOs.Cast<MgaFCO>())
                            {
                                foreach (var conn in elem.PartOfConns.Cast<IMgaConnPoint>())
                                {
                                    var dest = (conn.Owner as MgaSimpleConnection).Dst;
                                    dest.ParentModel.BoolAttrByName["THREATDETECTED"] = true;

                                    foreach (var child in dest.ParentModel.ChildFCOs.Cast<MgaFCO>())
                                    {
                                        
                                        if (child.Name == "OutputProduct")
                                        {
                                            foreach (var conn2 in child.PartOfConns.Cast<IMgaConnPoint>())
                                            {
                                                var parMod = (conn2.Owner as MgaSimpleConnection).Src.ParentModel;
                                                parMod.BoolAttrByName["THREATDETECTED"] = true;
                                            }
                                        }
                                    }

                                }
                            }

                            //follow connection to Process
                            //go inside topology
                            //for each facet
                            //print facet
                            //print WCS
                        }
                        else
                        {
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<div style='background-color:darkgreen; border: 5px solid; margin:5px; padding:5px; border-radius:5px'>" + proj.Name + "<i style='color: gray'> (Model of type " + proj.Meta.Name + ")</i><br>"));
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<i style='color: white'>" + "SAFE: SOFTWARE NOT REGISTERED IN NIST DATABASE" + "</i>"));
                        }
                    }


                }
                else if (proj.Meta.Name == "Human_Asset") //if the model is a human
                {
                    foreach (MgaAttribute attr in proj.Attributes)
                    {
                        if (attr.Value.ToString().Contains("Manager"))
                        {
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<div style='background-color:darkgreen; border: 5px solid; margin:5px; padding:5px; border-radius:5px'>" + proj.Name + "<i style='color: gray'> (Model of type " + proj.Meta.Name + ")</i><br>"));
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<i style='color: white'>" + "SAFE: MANAGERS WILL HAVE PASSED EXTENSIVE BACKGROUND CHECKS" + "</i>"));
                        }
                        else //we are an ordinary worker
                        {
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<div style='background-color:orange; border: 5px solid; margin:5px; padding:5px; border-radius:5px'>" + proj.Name + "<i style='color: gray'> (Model of type " + proj.Meta.Name + ")</i><br>"));
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<i style='color: darkgreen'>" + "Possibly UNSAFE: SOLO WORKER COULD COMMIT SABOTAGE" + "</i>"));

                        }
                    }
                    
                }
                else
                {
                    //don't care, will handle below
                }
                
                foreach (MgaAttribute attr in proj.Attributes)
                {
                    var name = attr.Meta.Name; // name of the attribute
                    var value = attr.Value; // value of the attribute
                    myOutput.Add(name + ": " + value + "<br>");
                }
                
                var temp = processAsOriginallyIntended(proj as MgaModel, indentLevel + 1);
                foreach (string i in temp)
                {
                    myOutput.Add(writeAtIndentLevel(0, i));
                }
                myOutput.Add(writeAtIndentLevel(indentLevel, "</div>"));
            }
            return myOutput;
        }

        public System.Collections.ArrayList processVolatileElements(MgaFCO proj, int indentLevel)
        {
            System.Collections.ArrayList myOutput = new System.Collections.ArrayList();

            //if the element is a model
            if (proj is MgaModel)
            {
                var whatIsThis = isSoftwareOrOS(proj as MgaModel);
                bool flag = true;
                if ((whatIsThis == "software") || (whatIsThis == "os")) //if the model is software or OS...
                {
                  //already handled software and os above
                }
                else if (proj.Meta.Name == "Human_Asset") //if the model is a human
                {
                    foreach (MgaAttribute attr in proj.Attributes)
                    {
                        if (attr.Value.ToString().Contains("Manager"))
                        {
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<div style='background-color:darkgreen; border: 5px solid; margin:5px; padding:5px; border-radius:5px'>" + proj.Name + "<i style='color: gray'> (Model of type " + proj.Meta.Name + ")</i><br>"));
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<i style='color: white'>" + "SAFE: MANAGERS WILL HAVE PASSED EXTENSIVE BACKGROUND CHECKS" + "</i>"));
                        }
                        else //we are an ordinary worker
                        {
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<div style='background-color:orange; border: 5px solid; margin:5px; padding:5px; border-radius:5px'>" + proj.Name + "<i style='color: gray'> (Model of type " + proj.Meta.Name + ")</i><br>"));
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<i style='color: darkgreen'>" + "Possibly UNSAFE: SOLO WORKER COULD COMMIT SABOTAGE" + "</i>"));

                        }
                    }
                }
                else
                {
                    try{
                        if (proj.BoolAttrByName["THREATDETECTED"] == true)
                        {
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<div style='background-color:red; border: 5px solid; margin:5px; padding:5px; border-radius:5px'>" + proj.Name + "<i style='color: gray'> (Model of type " + proj.Meta.Name + ")</i><br>"));
                        }
                        else if (proj.BoolAttrByName["WORSTCASESCENARIO"] == true)
                        {
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<div style='background-color:yellow; border: 5px solid; margin:5px; padding:5px; border-radius:5px'>" + proj.Name + "<i style='color: gray'> (Model of type " + proj.Meta.Name + ")</i><br>"));
                        }
                        else
                        {
                            myOutput.Add(writeAtIndentLevel(indentLevel, "<div style='background-color:lightgreen; border: 5px solid; margin:5px; padding:5px; border-radius:5px'>" + proj.Name + "<i style='color: gray'> (Model of type " + proj.Meta.Name + ")</i><br>"));
                        }
                    }
                    catch(Exception e){
                        myOutput.Add(writeAtIndentLevel(indentLevel, "<div style='background-color:lightgreen; border: 5px solid; margin:5px; padding:5px; border-radius:5px'>" + proj.Name + "<i style='color: gray'> (Model of type " + proj.Meta.Name + ")</i><br>"));

                    }
                }

                foreach (MgaAttribute attr in proj.Attributes)
                {
        
                    var name = attr.Meta.Name; // name of the attribute
                    var value = attr.Value; // value of the attribute
                    if ((name == "THREATDETECTED") || (name == "WORSTCASESCENARIO"))
                    {
                    }
                    myOutput.Add(name + ": " + value + "<br>");
                }

                var temp = processAsOriginallyIntended(proj as MgaModel, indentLevel + 1);
                foreach (string i in temp)
                {
                    myOutput.Add(writeAtIndentLevel(0, i));
                }
                myOutput.Add(writeAtIndentLevel(indentLevel, "</div>"));

            }
            else if (proj is MgaAtom)
            {
                myOutput.Add(writeAtIndentLevel(indentLevel, "" + proj.Name + "<i style='color: gray'> (Atom of type " + proj.Meta.Name + ")</i><br>"));

            }
            else
            {
                myOutput.Add(writeAtIndentLevel(indentLevel, "" + proj.Name + "<i style='color: gray'> (Component of type " + proj.Meta.Name + ")</i><br>"));

            }

            return myOutput;
        }

        //returns true if the model is a software or OS node, false otherwise.
        public string isSoftwareOrOS(MgaModel asset)
        {
            switch (asset.Meta.Name)
            {
                //software
                case "Software_Asset":
                case "Makerbot_Software":
                    return "software";
                //Linux OS
                case "Indirect_Dependency":
                case "Fedora": 
                case "Debian":
                case "Other_Linux_Distro":
                case "Ubuntu":
                case "Chrome_OS":
                case "Android_OS":
                //Windows versions
                case "Windows_XP":
                case "Windows_Vista":
                case "Windows_7":
                case "Windows_8":
                case "Windows_8point1":
                case "Windows 10":
                case "Windows_Server_2003":
                case "Windows_Server_2003_R2":
                case "Windows_Server_2008":
                case "Windows_Server_2008_R2":
                case "Windows_Server_2012":
                case "Windows_Server_2012_R2":
                //Mac OS versions
                case "v5_Leopard":
                case "v6_Snow_Leopard":
                case "v7_Lion":
                case "v8_Mountain_Lion":
                case "v9_Mavericks":
                case "v10_Yosemite":
                case "v11_El_Capitan":
                    return "os";
                default:
                    return "false";
            }
        }

        /** This function is always called on a model of type Industrial_Model */
        public System.Collections.ArrayList process(MgaModel m, int indentLevel)
        {
            System.Collections.ArrayList myOutput = new System.Collections.ArrayList();
            foreach (var proj in m.ChildFCOs.Cast<MgaFCO>())
            {
                var result=new ArrayList();
                if (proj is MgaModel)
                {
                    if ((isSoftwareOrOS(proj as MgaModel) == "software") || (isSoftwareOrOS(proj as MgaModel) == "os"))
                    {
                        result = processSoftware(proj, indentLevel);
                    }
                    else
                    {
                        result = processVolatileElements(proj, indentLevel);
                    }
                }
     
                foreach (string str in result)
                {
                    myOutput.Add(str);
                }

            }
            return myOutput;
        }

        public System.Collections.ArrayList processAsOriginallyIntended(MgaModel m, int indentLevel)
        {
            System.Collections.ArrayList myOutput = new System.Collections.ArrayList();

            foreach (var proj in m.ChildFCOs.Cast<MgaFCO>())
            {
              
                var result = processVolatileElements(proj, indentLevel);

                foreach (string str in result)
                {
                    myOutput.Add(str);
                }

            }
            return myOutput;
        }

        //helpful fn for simplifying indenting
        public string writeAtIndentLevel(int level, string text)
        {
            for (int i = 0; i < level; i++)
            {
                text = "&nbsp&nbsp&nbsp&nbsp&nbsp" + text;
            }
            return text;
        }

        //writes to file the array of strings it is passed
        public void writeToFile(System.Collections.ArrayList myArray, string fileName)
        {
            using (StreamWriter outputFile = new StreamWriter(fileName))
            {
                foreach(string elem in myArray){
                    outputFile.WriteLine(elem);
                }
                GMEConsole.Out.WriteLine("Open file " + fileName + " , found in same directory as model, to view results");
            }
        }

        #region IMgaComponentEx Members

        MgaGateway MgaGateway { get; set; }
        GMEConsole GMEConsole { get; set; }

        public void InvokeEx(MgaProject project, MgaFCO currentobj, MgaFCOs selectedobjs, int param)
        {
            if (!enabled)
            {
                return;
            }

            try
            {
                GMEConsole = GMEConsole.CreateFromProject(project);
                MgaGateway = new MgaGateway(project);
                project.CreateTerritoryWithoutSink(out MgaGateway.territory);

                MgaGateway.PerformInTransaction(delegate
                {
                    Main(project, currentobj, selectedobjs, Convert(param));
                });
            }
            finally
            {
                if (MgaGateway.territory != null)
                {
                    MgaGateway.territory.Destroy();
                }
                MgaGateway = null;
                project = null;
                currentobj = null;
                selectedobjs = null;
                GMEConsole = null;
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }

        private ComponentStartMode Convert(int param)
        {
            switch (param)
            {
                case (int)ComponentStartMode.GME_BGCONTEXT_START:
                    return ComponentStartMode.GME_BGCONTEXT_START;
                case (int)ComponentStartMode.GME_BROWSER_START:
                    return ComponentStartMode.GME_BROWSER_START;

                case (int)ComponentStartMode.GME_CONTEXT_START:
                    return ComponentStartMode.GME_CONTEXT_START;

                case (int)ComponentStartMode.GME_EMBEDDED_START:
                    return ComponentStartMode.GME_EMBEDDED_START;

                case (int)ComponentStartMode.GME_ICON_START:
                    return ComponentStartMode.GME_ICON_START;

                case (int)ComponentStartMode.GME_MAIN_START:
                    return ComponentStartMode.GME_MAIN_START;

                case (int)ComponentStartMode.GME_MENU_START:
                    return ComponentStartMode.GME_MENU_START;
                case (int)ComponentStartMode.GME_SILENT_MODE:
                    return ComponentStartMode.GME_SILENT_MODE;
            }

            return ComponentStartMode.GME_SILENT_MODE;
        }

        #region Component Information
        public string ComponentName
        {
            get { return GetType().Name; }
        }

        public string ComponentProgID
        {
            get
            {
                return ComponentConfig.progID;
            }
        }

        public componenttype_enum ComponentType
        {
            get { return ComponentConfig.componentType; }
        }
        public string Paradigm
        {
            get { return ComponentConfig.paradigmName; }
        }
        #endregion

        #region Enabling
        bool enabled = true;
        public void Enable(bool newval)
        {
            enabled = newval;
        }
        #endregion

        #region Interactive Mode
        protected bool interactiveMode = true;
        public bool InteractiveMode
        {
            get
            {
                return interactiveMode;
            }
            set
            {
                interactiveMode = value;
            }
        }
        #endregion

        #region Custom Parameters
        SortedDictionary<string, object> componentParameters = null;

        public object get_ComponentParameter(string Name)
        {
            if (Name == "type")
                return "csharp";

            if (Name == "path")
                return GetType().Assembly.Location;

            if (Name == "fullname")
                return GetType().FullName;

            object value;
            if (componentParameters != null && componentParameters.TryGetValue(Name, out value))
            {
                return value;
            }

            return null;
        }

        public void set_ComponentParameter(string Name, object pVal)
        {
            if (componentParameters == null)
            {
                componentParameters = new SortedDictionary<string, object>();
            }

            componentParameters[Name] = pVal;
        }
        #endregion

        #region Unused Methods
        // Old interface, it is never called for MgaComponentEx interfaces
        public void Invoke(MgaProject Project, MgaFCOs selectedobjs, int param)
        {
            throw new NotImplementedException();
        }

        // Not used by GME
        public void ObjectsInvokeEx(MgaProject Project, MgaObject currentobj, MgaObjects selectedobjs, int param)
        {
            throw new NotImplementedException();
        }

        #endregion

        #endregion

        #region IMgaVersionInfo Members

        public GMEInterfaceVersion_enum version
        {
            get { return GMEInterfaceVersion_enum.GMEInterfaceVersion_Current; }
        }

        #endregion

        #region Registration Helpers

        [ComRegisterFunctionAttribute]
        public static void GMERegister(Type t)
        {
            Registrar.RegisterComponentsInGMERegistry();

        }

        [ComUnregisterFunctionAttribute]
        public static void GMEUnRegister(Type t)
        {
            Registrar.UnregisterComponentsInGMERegistry();
        }

        #endregion


    }
}
/*
//Windows versions
                case "Windows_XP":
                    break;
                case "Windows_Vista":
                    break;
                case "Windows_7":
                    break;
                case "Windows_8":
                    break;
                case "Windows_8point1":
                    break;
                case "Windows 10":
                    break;
                case "Windows_Server_2003":
                    break;
                case "Windows_Server_2003_R2":
                    break;
                case "Windows_Server_2008":
                    break;
                case "Windows_Server_2008_R2":
                    break;
                case "Windows_Server_2012":
                    break;
                case "Windows_Server_2012_R2":
                    break;
                //Mac OS versions
                case "v5_Leopard":
                    break;
                case "v6_Snow_Leopard":
                    break;
                case "v7_Lion":
                    break;
                case "v8_Mountain_Lion":
                    break;
                case "v9_Mavericks":
                    break;
                case "v10_Yosemite":
                    break;
                case "v11_El_Capitan":
                    break;

//product types
                case "RawProduct":
                case "IntermediateProduct":
                case "FinishedProduct":
                case "Waste_Product":
                    return false;
                //human assets
                case "Human_Asset":
                    return "Human";
                //physical assets
                case "Physical_Asset":
                case "Makerbot_Replicator_Two":
                    return "Physical";
                //software assets
                case "Software_Asset":
                case "Makerbot_Software":
                    return "Software";
                //topology classes
                case "Product_Topology":
                case "Worst_Case_Scenario":
                case "Vulnerability_Facet":
                    return "Topology";
                //OS and Sandbox
                case "Indirect_Dependency":
                case "Fedora": 
                case "Debian":
                case "Other_Linux_Distro":
                case "Ubuntu":
                case "Chrome_OS":
                    return "Linux OS";
                case "Android_OS":
                    return "Android OS";
                //Windows versions
                case "Windows_XP":
                case "Windows_Vista":
                case "Windows_7":
                case "Windows_8":
                case "Windows_8point1":
                case "Windows 10":
                case "Windows_Server_2003":
                case "Windows_Server_2003_R2":
                case "Windows_Server_2008":
                case "Windows_Server_2008_R2":
                case "Windows_Server_2012":
                case "Windows_Server_2012_R2":
                    return "Windows OS";
                //Mac OS versions
                case "v5_Leopard":
                case "v6_Snow_Leopard":
                case "v7_Lion":
                case "v8_Mountain_Lion":
                case "v9_Mavericks":
                case "v10_Yosemite":
                case "v11_El_Capitan":
                    return "Mac OS";
                default:
                    return "process"; */