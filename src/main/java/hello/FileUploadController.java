package hello;


import edu.umass.cs.gnscommon.exceptions.client.ClientException;
import hello.storage.StorageFileNotFoundException;
import hello.storage.StorageService;
import org.json.HTTP;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;


import edu.umass.cs.gnsclient.client.GNSClient;
import edu.umass.cs.gnsclient.client.GNSCommand;
import edu.umass.cs.gnsclient.client.util.GuidEntry;
import edu.umass.cs.gnsclient.client.util.GuidUtils;
import edu.umass.cs.gnscommon.SharedGuidUtils;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;


import org.springframework.boot.autoconfigure.web.ErrorController;

@Controller
public class FileUploadController implements ErrorController{

    private final StorageService storageService;
    private static String certificate_file_name;
    private static String private_key_file_name;

    private static final String reconfigurator_hostname = "127.0.0.1";
    private static GNSClient gnsClient = null;
    private static GuidEntry GUID;

    protected final static String RECORD_FIELD = "record";
    protected final static String TTL_FIELD = "ttl";


    private final static int TTL = 30;
    private static final String A_FIELD = "A";
    private static final String NS_FIELD = "NS";
    private static final String CNAME_FIELD = "CNAME";
    private static final String PATH = "/error";
    private static final String DEFAULT_PASSWORD = "password";


    private static String DEFAULT_IP = null;
    private static String guid_name = null;


    @RequestMapping(value = PATH)
    public String error() {
        return "error-page";
    }

    @Override
    public String getErrorPath() {
        return PATH;
    }

    @Autowired
    public FileUploadController(StorageService storageService) {
        this.storageService = storageService;
    }


    /**
     *
     * FUnction to handle get request for url /
     * @return outupu-template
     * @throws IOException
     */

    @GetMapping("/")
    public String showLandingPage() throws IOException {
        if ( certificate_file_name != null && private_key_file_name != null && gnsClient != null) {
            return "redirect:/home";
        }

        return "redirect:/index.html";
    }


    /**
     * Function to handle post request for url /makedefaultentry
     *
     * @param file1 certificate
     * @param file2 private key
     * @return success-http response
     * @throws IOException
     */

    @PostMapping("/makedefaultentry")
    public ResponseEntity<?> makeDefaultEntry(@RequestParam("file1") MultipartFile file1,
                                   @RequestParam("file2") MultipartFile file2) throws IOException {


        storageService.store(file1);
        storageService.store(file2);

        String cert_path= System.getProperty("user.dir") + "/upload-dir/" + file1.getOriginalFilename();
        String private_key_path = System.getProperty("user.dir") + "/upload-dir/" + file2.getOriginalFilename();

        GNSClient client = new GNSClient(reconfigurator_hostname);
        client.setForceCoordinatedReads(true);

        GuidEntry tempGuid = lookupOrCreateAccount(client, cert_path, private_key_path);

        if(DEFAULT_IP == null) {
            try {
                InetAddress address = InetAddress.getByName("default.opengns.com");
                DEFAULT_IP = address.getHostAddress();
                System.out.println(DEFAULT_IP);
            } catch (UnknownHostException e) {
                System.out.println("default hostlookup failed");
                return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
            }
        }

        List<String> arecords = Arrays.asList(DEFAULT_IP);
        JSONObject arecordObj = createArecords(arecords, TTL);

        if(!updateFieldUsingClient(client, tempGuid, A_FIELD, arecordObj)) {
            client.close();
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

        client.close();
        return new ResponseEntity<>(HttpStatus.OK);
    }

    /**
     * Function to handle post request for the url /uploadkeys
     * @param file1 certiifcate
     * @param file2 privatekey
     * @return output-template file
     * @throws IOException while storing the file
     */

    @PostMapping("/uploadkeys")
    public String handleFileUpload(@RequestParam("file1") MultipartFile file1,
                                   @RequestParam("file2") MultipartFile file2) throws IOException{

        try {
            storageService.deleteAll();

            storageService.store(file1);
            storageService.store(file2);


            certificate_file_name = System.getProperty("user.dir") + "/upload-dir/" + file1.getOriginalFilename();
            private_key_file_name = System.getProperty("user.dir") + "/upload-dir/" + file2.getOriginalFilename();

            if(gnsClient == null) {
                System.out.println(reconfigurator_hostname);
                gnsClient = new GNSClient(reconfigurator_hostname);
                gnsClient.setForceCoordinatedReads(true);
            }

        }catch (Exception e) {
            System.out.println("Unknown exception occured while uploading the credentials ");
            e.printStackTrace();
            return "unknown-error";
        }

        return "redirect:/home";
    }

    /**
     * Helper function to read A records from server.
     * @return comma separated list of A records
     * @throws IOException
     * @throws JSONException
     */

    public static String readArecordsFromServer() throws IOException, JSONException {

        String outputString = "";

        try {
            String resultString =  gnsClient.execute(GNSCommand.fieldExists(GUID, A_FIELD)).getResultString();
            JSONObject completeObj = new JSONObject(resultString);
            JSONArray recordArray = completeObj.getJSONObject(A_FIELD).getJSONArray("record");

            for (int i = 0; i< recordArray.length() ; i++){
                outputString += recordArray.get(i) + ",  ";
            }
            System.out.println(outputString);

        }catch (ClientException e) {
            System.out.println("Unable to check attribute" + A_FIELD);
        }

        return outputString;
    }


    /**
     * Helper function to read ns records from gns server
     * @return comma separated list of ns records
     * @throws IOException
     * @throws JSONException
     */
    public static String readNSrecordsFromServer() throws IOException, JSONException{
        String outputString = "";

        try {
            String resultString =  gnsClient.execute(GNSCommand.fieldExists(GUID, NS_FIELD)).getResultString();
            JSONObject completeObj = new JSONObject(resultString);
            JSONArray recordArray = completeObj.getJSONObject(NS_FIELD).getJSONArray("record");

            for (int i = 0; i< recordArray.length() ; i++){
                JSONArray nsRecord = recordArray.getJSONArray(i);
                outputString += nsRecord.get(0) + ",  " + nsRecord.get(1);
            }
            System.out.println(outputString);

        }catch (ClientException e) {
            System.out.println("Unable to check attribute" + NS_FIELD);
        }

        return outputString;
    }


    /**
     *
     * Helper function read cname from server.
     * @return cname from server
     * @throws IOException
     * @throws JSONException
     */

    public static String readCnameFromServer() throws IOException, JSONException {
        String outputString = "";

        try {
            String resultString =  gnsClient.execute(GNSCommand.fieldExists(GUID, CNAME_FIELD)).getResultString();
            JSONObject obj  = new JSONObject(resultString);
            outputString += obj.get(CNAME_FIELD);

        }catch (ClientException e) {
            System.out.println("Unable to check attribute" + NS_FIELD);
        }

        return outputString;
    }

    /**
     * Helper  function to do a lookup for the user
     *
     * @param client GNSclient
     * @param certfilename absolute path for the certificate file name
     * @param privatekeyfilename absolute pathe for the private key file name
     * @return guid of the user
     */
    private static GuidEntry lookupOrCreateAccount(GNSClient client, String certfilename, String privatekeyfilename) {
        try {
            GuidEntry guidEntry = GuidUtils.lookupOrCreateAccountGuidWithCertificate(client, certfilename,
                    privatekeyfilename, DEFAULT_PASSWORD, true);
            return guidEntry;
        }catch (Exception e) {
            System.out.println("Exception while creating the guid");
            System.out.println(e.getMessage());
            e.printStackTrace();
            return null;
        }
    }


    /**
     *
     *  Function to generate home page for  user.
     * @param model placeholder to add dynamic content on static html  page
     * @return
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws JSONException
     */
    @RequestMapping("/home")
    public String home( Model model) throws IOException,
            CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, JSONException {

        if ( certificate_file_name == null || private_key_file_name == null || gnsClient == null) {
            return "redirect:/";
        }

        if (GUID == null | gnsClient == null ) {

            X509Certificate cert = SharedGuidUtils.loadCertificateFromFile(certificate_file_name);
            guid_name = SharedGuidUtils.getNameFromCertificate(cert);

            GUID = lookupOrCreateAccount(gnsClient, certificate_file_name, private_key_file_name);
            if (GUID == null) {
                return "unknown-error";
            }
        }

        //check if A record, NS record exists
        String arecord = readArecordsFromServer();
        String nsrecord = readNSrecordsFromServer();
        String cname = readCnameFromServer();

        model.addAttribute("name", guid_name);
        model.addAttribute("arecord", arecord);
        model.addAttribute("nsrecord", nsrecord);
        model.addAttribute("cname", cname);
        return "homepage";
    }

    /**
     *
     * Helper function to update field of guid using a gns client
     * @param client GNS client
     * @param guidEntry guid
     * @param fieldName field name
     * @param obj json object that needs to be updated
     * @return true on success, false on failure
     */
    public static boolean updateFieldUsingClient(GNSClient client,GuidEntry guidEntry, String fieldName, Object obj) {
        try {
            client.execute(GNSCommand.fieldUpdate(guidEntry, fieldName, obj));
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            return false;
        }

        return true;
    }


    /**
     * Function to handle get request for url /dnsrecords
     *
     * @param arecord  arecords
     * @param nsrecord ns records
     * @param cname cname records
     * @return success page if update is successful, failure page if update is failure
     * @throws IOException
     * @throws FileNotFoundException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    @RequestMapping("/dnsrecords")
    public String handleUpdateRecords(@RequestParam("arecord") String arecord,
                                      @RequestParam("nsrecord") String nsrecord,
                                      @RequestParam("cname") String cname) throws IOException, FileNotFoundException,
            CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {


        List<String> arecords = Arrays.asList(arecord.split(","));
        JSONObject arecordObj = createArecords(arecords, TTL);

        List<String> nsrecords = Arrays.asList(nsrecord.split(","));
        JSONObject nsrecordObj = createNSrecords(nsrecords, TTL);


        if(!updateFieldUsingClient(gnsClient, GUID, A_FIELD, arecordObj))
            return "failure";

        if(!updateFieldUsingClient(gnsClient, GUID, NS_FIELD, nsrecordObj))
            return "failure";

        if(!updateFieldUsingClient(gnsClient, GUID, CNAME_FIELD, cname))
            return "failure";

        return "success";
    }

    /**
     * Function to clean the session and close user session
     * @return logout template
     */
    @RequestMapping("/logout")
    public String handleLogout(){
        storageService.deleteAll();
        gnsClient = null;
        GUID = null;
        guid_name = null;
        return "logout";
    }


    @ExceptionHandler(StorageFileNotFoundException.class)
    public ResponseEntity handleStorageFileNotFound(StorageFileNotFoundException exc) {
        return ResponseEntity.notFound().build();
    }

    /**
     * Helper function to create A records in JSON object format from a list of ips
     * @param ips list of ips
     * @param ttl ttl field for these A records
     * @return
     */
    public static JSONObject createArecords(List<String> ips, int ttl) {
        JSONObject recordObj = new JSONObject();
        JSONArray records = new JSONArray();
        for (String ip:ips){
            if(ip.trim().length() == 0)
                continue;
            records.put(ip.trim());
        }

        try {
            recordObj.put(RECORD_FIELD, records);
            recordObj.put(TTL_FIELD, ttl);
        } catch (JSONException e) {
            System.out.println("Unexpected json exception ");
            e.printStackTrace();
        }
        return recordObj;
    }

    /**
     * Helper function to  create NS records in JSON object from a list of ns records
     * @param input list of ns records
     * @param ttl ttl field for these ns records
     * @return
     */

    public static JSONObject createNSrecords(List<String> input, int ttl) {
        JSONObject recordObj = new JSONObject();
        JSONArray records = new JSONArray();
        int i = 0;

        while(i < input.size()) {
            // first argument cannot be empty if empty break
            JSONArray tempArray = new JSONArray();
            if (input.get(i).length() == 0)
                break;

            tempArray.put(input.get(i).trim());
            tempArray.put(input.get(i+1).trim());

            records.put(tempArray);
            i = i+2;
        }

        try {
            recordObj.put(RECORD_FIELD, records);
            recordObj.put(TTL_FIELD, ttl);
        } catch (JSONException e) {
            System.out.println("Unexpected json exception in ns records");
            e.printStackTrace();
        }

        return recordObj;
    }

}
