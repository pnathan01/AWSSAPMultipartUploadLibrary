package company.com_co_xi_app_global_fl;

import com.sap.aii.mapping.api.*;
import com.sap.aii.mapping.lookup.*;
import com.sap.aii.mappingtool.tf7.rt.*;
import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import java.net.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import com.sap.engine.interfaces.messaging.api.*;
import com.sap.engine.interfaces.messaging.api.auditlog.*;
import com.sap.ide.esr.tools.mapping.core.ExecutionType;
import com.sap.ide.esr.tools.mapping.core.Argument;
import com.sap.ide.esr.tools.mapping.core.Cleanup;
import com.sap.ide.esr.tools.mapping.core.LibraryMethod;
import com.sap.ide.esr.tools.mapping.core.Init;


public class FL_COMP_AWS  {



	@Init(description="") 
	public void init (
		 GlobalContainer container)  throws StreamTransformationException{
		
	}

	@Cleanup 
	public void cleanup (
		 GlobalContainer container)  throws StreamTransformationException{
		
	}

	@LibraryMethod(title="getMetadataValues", description="", category="FL_COMP_AWS", type=ExecutionType.ALL_VALUES_OF_QUEUE) 
	public void getMetadataValues (
		 ResultList result,
		@Argument(title="")  String[] key,
		 Container container)  throws StreamTransformationException{
				GlobalContainer globalContainer = container.getGlobalContainer();
		Map<String, String> mpuData = (HashMap<String, String>) globalContainer.getParameter("mpuData");
		Map<String, String> treeMap = new TreeMap(mpuData);


		List<String> sortedHeaders = new ArrayList<String>();
		sortedHeaders.addAll(mpuData.keySet());
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER);
        
        //StringBuilder buffer = new StringBuilder();
        loadAuditMessage("MetaData File Contents",container);
        for (Map.Entry<String, String> helement : treeMap.entrySet()) {
        	String keyVal = (String)helement.getKey();
	        if (keyVal.contains(key[0])) {
	        	result.addValue((String)helement.getValue());
	        }
	        loadAuditMessage((keyVal+":"+(String)helement.getValue()),container);
        }
	}

	@LibraryMethod(title="getMetadataFileContents", description="", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String getMetadataFileContents (
		 Container container)  throws StreamTransformationException{
			GlobalContainer globalContainer = container.getGlobalContainer();
		String content = "";
		String fileContentStr = "";
		String fileNamePattern = "Temp_Metadata.txt";
		boolean StartsWithStr_Found = false;
		String filePath = getDynamicParameters("Directory", container);
		Map<String, String> mpuData = (HashMap<String, String>) globalContainer.getParameter("mpuData");

		if (filePath != null && filePath != "") {
		    File[] dirFiles = new File(filePath).listFiles();
		    if (dirFiles.length > 0) {
		        for (int i = 0; i < dirFiles.length; i++) {
		            String fileNameStr = dirFiles[i].getName();
		            if (fileNameStr.contains(fileNamePattern)) {
		                StartsWithStr_Found = true;

		                BufferedReader br = null;
		                try {
		                    String sCurrentLine;
		                    br = new BufferedReader(new FileReader(filePath + "/" + fileNameStr));
		                    while ((sCurrentLine = br.readLine()) != null) {
		                        fileContentStr = fileContentStr + sCurrentLine + "\n";
		                    }
		                } catch (IOException e) {
		                    loadAuditMessage("Error in reading metadata file for CompleteMPU", container);
		                } finally {
		                    try {
		                        if (br != null) br.close();
		                    } catch (IOException ex) {
		                        loadAuditMessage("Error in closing metadata file for CompleteMPU", container);
		                    }
		                }
		            }
		        }
		    }
		}
		if (fileContentStr != null || fileContentStr != "") {
		    String[] fileContents = fileContentStr.split("\n");
		    int eTagCount = 0;
		    for (String line: fileContents) {
		        if (line.contains("UPLOADPART")) {
		            String[] lineContents = line.split("ETAG:");
		            mpuData.put(((String.format("%02d",(eTagCount + 1)))+"ETag"), lineContents[1]);
		            mpuData.put(((String.format("%02d",(eTagCount + 1)))+"PartNumber"), Integer.toString(eTagCount + 1));
		            eTagCount++;
		        } else if(line.contains("CREATEMULTIPARTUPLOAD")) {
		        	String[] lineContents = line.split("UPLOADID:");
		        	mpuData.put("UPLOADID", lineContents[1]);
		        }
		    }
		}

		return content;
	}

	@LibraryMethod(title="computeSignature", description="Calculate the signature to be added onto Auth headaer", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String computeSignature (
		@Argument(title="Content Hash")  String contentHash,
		@Argument(title="AWS Access Key")  String awsAccessKey,
		@Argument(title="AWS Secret Key")  String awsSecretKey,
		@Argument(title="Bucket")  String bucketName,
		@Argument(title="Region")  String regionName,
		@Argument(title="File Name")  String filename,
		@Argument(title="Date")  String date,
		@Argument(title="Action")  String queryParameters,
		 Container container)  throws StreamTransformationException{
			GlobalContainer globalContainer = container.getGlobalContainer();
		AbstractTrace trace = container.getTrace();
		Map<String, String> headers = (HashMap<String, String>) globalContainer.getParameter("headers");		
		String signedHeaders = "";
		URL endpointURL = null;
		String algorithm = "HmacSHA256";
		Mac mac = null;
		
		//form URL
		try {
			if(queryParameters != null || queryParameters != "") {
				String endpoint = "https://" + bucketName + ".s3." + regionName + ".amazonaws.com/"+ filename
						+ "?" + queryParameters;
				if(endpoint.endsWith("=")){
					endpoint = endpoint.substring(0, endpoint.length() - 1);
				}
				endpointURL = new URL(endpoint);
			} else {
				endpointURL = new URL ("https://" + bucketName + ".s3." + regionName + ".amazonaws.com/"+ filename);
			}
			headers.put("1_URL", endpointURL.toString());
		} catch( Exception e ) {
			trace.addInfo("Unable to form endpoint URL");
		}
		trace.addInfo("URL: " + endpointURL);
		loadAuditMessage(("URL: " + endpointURL), container);
		// form Signed Headers
		signedHeaders = formSignedHeaders(signedHeaders, container);
		trace.addInfo("SignedHeaders: " + signedHeaders);
		loadAuditMessage(("SignedHeaders: " + signedHeaders), container);
		String httpMethod = readHashMapValuewithKey("1_httpMethod",container);
		// form Canonical Headers
		String canonicalHeaders = formCanonicalHeaders(container);
		String canonicalRequest = formCanonicalRequest(endpointURL.toString(), 
													   httpMethod,
													   signedHeaders,
													   canonicalHeaders,
													   queryParameters,
													   contentHash,
													   container);
		String scope = date + "/" +
					   regionName + "/" +
					   "s3/aws4_request" ;
		loadAuditMessage(("Scope: " + scope), container);
		String stringToSign =  formStringToSign(canonicalRequest, scope, container);
		trace.addInfo("String to sign: " + stringToSign);
		loadAuditMessage(("String to sign: " + stringToSign), container);
		String signature = "";
		try {
			mac = Mac.getInstance(algorithm);
			
			byte[] kSecret = ("AWS4" + awsSecretKey).getBytes("UTF-8");
			mac.init(new SecretKeySpec(kSecret, algorithm));
			
			byte[] kDate = mac.doFinal(date.getBytes("UTF-8"));
			mac.init(new SecretKeySpec(kDate, algorithm));

			byte[] kRegion = mac.doFinal(regionName.getBytes("UTF-8"));
			mac.init(new SecretKeySpec(kRegion, algorithm));
			
			byte[] kService =  mac.doFinal("s3".getBytes("UTF-8"));
			mac.init(new SecretKeySpec(kService, algorithm));
			
			byte[] kSigning = mac.doFinal("aws4_request".getBytes("UTF-8"));
			mac.init(new SecretKeySpec(kSigning, algorithm));
        
			byte[] kSignature = mac.doFinal(stringToSign.getBytes("UTF-8"));
			
			StringBuilder tempSign = new StringBuilder();
			for (byte b : kSignature) {
				tempSign.append(String.format("%02x", b));
			}	
			
			signature = tempSign.toString();
			
			trace.addInfo("Signature" + signature);
			loadAuditMessage(("Signature" + signature), container);
		} catch(Exception e) {
			loadAuditMessage("Unable to create key with algorithm", container);
		}
        
        String credentialsAuthorizationHeader =
                "Credential=" + awsAccessKey + "/" + scope;
        trace.addInfo("Credential: " + credentialsAuthorizationHeader );
        loadAuditMessage(("Credential: " + credentialsAuthorizationHeader ), container);
        String signedHeadersAuthorizationHeader = "SignedHeaders=" + signedHeaders;
        trace.addInfo("SignedHeaders: " + signedHeadersAuthorizationHeader);
        loadAuditMessage(("SignedHeaders: " + signedHeadersAuthorizationHeader), container);
        String signatureAuthorizationHeader =
                "Signature=" + signature;
        trace.addInfo("Signature" + signatureAuthorizationHeader );
        loadAuditMessage(("Signature" + signatureAuthorizationHeader ), container);
        
        String authorizationHeader = "AWS4-HMAC-SHA256 "
                + credentialsAuthorizationHeader + ", "
                + signedHeadersAuthorizationHeader + ", "
                + signatureAuthorizationHeader;
    trace.addInfo("AuthorizationHeader: " + authorizationHeader);
    loadAuditMessage(("AuthorizationHeader: " + authorizationHeader), container);
    return authorizationHeader;
	}

	@LibraryMethod(title="getQueryDetails", description="", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String getQueryDetails (
		@Argument(title="")  String scenario,
		 Container container)  throws StreamTransformationException{
			String queryString="";
		GlobalContainer globalContainer = container.getGlobalContainer();
		Map<String, String> mpuData = (HashMap<String, String>) globalContainer.getParameter("mpuData");
		Map<String, String> treeMap = new TreeMap(mpuData);


		List<String> sortedHeaders = new ArrayList<String>();
		sortedHeaders.addAll(mpuData.keySet());
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER);
        
        //StringBuilder buffer = new StringBuilder();
        int eTagCount = 0;
        String uploadID = "";
        for (Map.Entry<String, String> helement : treeMap.entrySet()) {
        	String keyVal = (String)helement.getKey();
	        if (keyVal.contains("UPLOADID")) {
	        	uploadID = (String)helement.getValue();
	        } else if(keyVal.contains("PartNumber")) {
	        	eTagCount++;
	        }
        }
		if(scenario == "UPLOAD_PART") {
			queryString = "partNumber=" + (eTagCount + 1) + "&" + "uploadId=" + uploadID;
		} else if(scenario == "COMPLETE_MULTIPART_UPLOAD" ) {
			queryString = "uploadId=" + uploadID;
		}
        
		return queryString;
	}

	@LibraryMethod(title="getQueryParameters", description="", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String getQueryParameters (
		@Argument(title="")  String scenario,
		 Container container)  throws StreamTransformationException{
			String queryParamString = "";
			
			if(scenario.contains("SINGLE_CHUNK_UPLOAD")) {
				queryParamString = "";
			} else if(scenario.contains("INITIATE_MULTIPART_UPLOAD")) {
				queryParamString = "uploads=";
			} else if(scenario.contains("COMPLETE_MULTIPART_UPLOAD")) {
				queryParamString = getQueryDetails("COMPLETE_MULTIPART_UPLOAD", container);
			}else if(scenario.contains("UPLOAD_PART")) {
				queryParamString = getQueryDetails("UPLOAD_PART", container);
			} else {
				queryParamString = "";
			}
	
		return queryParamString;
	}

	@LibraryMethod(title="readHashMapValuewithKey", description="", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String readHashMapValuewithKey (
		@Argument(title="Key")  String key,
		 Container container)  throws StreamTransformationException{
			GlobalContainer globalContainer = container.getGlobalContainer();
		Map<String, String> headers = (HashMap<String, String>) globalContainer.getParameter("headers");
		Map<String, String> treeMap = new TreeMap(headers);
		String elemVal = "";

		for(Map.Entry<String, String> helement : treeMap.entrySet()) {
			String keyVal = (String)helement.getKey();
			if(keyVal.contains(key)) {
				elemVal = (String)helement.getValue();
			}
		}
		return elemVal;
	}

	@LibraryMethod(title="defineReqParameters", description="Define file name related parameters that will define the process", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String defineReqParameters (
		@Argument(title="File Name")  String filename,
		@Argument(title="Action")  String action,
		 Container container)  throws StreamTransformationException{
			GlobalContainer globalContainer = container.getGlobalContainer();
		@SuppressWarnings("unchecked")
		Map<String, String> headers = (HashMap<String, String>) globalContainer.getParameter("headers");
		
		if(action.contains("SINGLE_CHUNK_UPLOAD")) {		// Single Chunk Upload File 
			headers.put("1_httpMethod", "PUT");
			headers.put("0_"+"x_amz_storage_class", "REDUCED_REDUNDANCY");
			headers.put("1_QueryParams", getQueryParameters("SINGLE_CHUNK_UPLOAD", container));
		} else if(action.contains("MULTIPART_UPLOAD")) {
			if(filename.contains("00000000")) {			// Initiate Multipart Upload File
				headers.put("1_httpMethod", "POST");
				headers.put("0_"+"x_amz_storage_class", "REDUCED_REDUNDANCY");
				headers.put("1_QueryParams", getQueryParameters("INITIATE_MULTIPART_UPLOAD", container));
			} else if(filename.contains("99999999")) {		// Complete Multipart Upload File
				headers.put("1_httpMethod", "POST");
//				headers.put("0_"+"x_amz_storage_class", "REDUCED_REDUNDANCY");
				headers.put("1_QueryParams", getQueryParameters("COMPLETE_MULTIPART_UPLOAD", container));
			} else {										// Upload Part File
				headers.put("1_httpMethod", "PUT");
				headers.put("1_QueryParams", getQueryParameters("UPLOAD_PART", container));
			}
		}
		
		return null;
	}

	@LibraryMethod(title="formCompleteMPUContent", description="", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String formCompleteMPUContent (
		 Container container)  throws StreamTransformationException{
			GlobalContainer globalContainer = container.getGlobalContainer();
		String content = "";
	 //"<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "\n" +
//			String contentBegin =  "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" + "\n";
			String contentBegin =  "<CompleteMultipartUpload>";
		String contentTags = "";
		String contentEnd = "</CompleteMultipartUpload>";
		Map<String, String> mpuData = (HashMap<String, String>) globalContainer.getParameter("mpuData");
		Map<String, String> treeMap = new TreeMap(mpuData);


		List<String> sortedHeaders = new ArrayList<String>();
		sortedHeaders.addAll(mpuData.keySet());
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER);
        
        //StringBuilder buffer = new StringBuilder();
        for (Map.Entry<String, String> helement : treeMap.entrySet()) {
        	String keyVal = (String)helement.getKey();
	        if (keyVal.contains("ETag")) {
	            contentTags = contentTags + "<Part>" +
	                "<ETag>" +  (String)helement.getValue() + "</ETag>";
	        } else if(keyVal.contains("PartNumber")) {
	        	contentTags = contentTags + "<PartNumber>" + (String)helement.getValue() + "</PartNumber>"
		        + "</Part>";
	        }
        }
        content = contentBegin + contentTags + contentEnd;
		return content;
	}

	@LibraryMethod(title="loadAuditMessage", description="", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String loadAuditMessage (
		@Argument(title="")  String inputMessage,
		 Container container)  throws StreamTransformationException{
			// Get Message Id
	String msgID=container.getInputHeader().getMessageId();

// Form Message Key to add to audit log
	String DASH = "-";
	String uuidTimeLow = msgID.substring(0, 8);
	String uuidTimeMid = msgID.substring(8, 12);
	String uuidTimeHighAndVersion = msgID.substring(12, 16);
	String uuidClockSeqAndReserved = msgID.substring(16, 18);
	String uuidClockSeqLow = msgID.substring(18, 20);
	String uuidNode = msgID.substring(20, 32);
	String msgUUID = uuidTimeLow + DASH + 
					 uuidTimeMid + DASH + 
					 uuidTimeHighAndVersion + DASH + 
					 uuidClockSeqAndReserved + uuidClockSeqLow + 
					 DASH + uuidNode;
// Construct message key (com.sap.engine.interfaces.messaging.api.MessageKey)
// for retrieved message ID and outbound message direction (com.sap.engine.interfaces.messaging.api.MessageDirection).
	try{
	MessageKey msgKey = new MessageKey(msgUUID, MessageDirection.OUTBOUND);
	AuditAccess audit = PublicAPIAccessFactory.getPublicAPIAccess().getAuditAccess();
    audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, inputMessage);
	} catch(Exception e) {
		return "Error while trying to display message";
	}
	return null;
	}

	@LibraryMethod(title="loadDynamicParameters", description="Load all calculated values into dynamic parameters", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String loadDynamicParameters (
		 Container container)  throws StreamTransformationException{
			GlobalContainer globalContainer = container.getGlobalContainer();
		AbstractTrace trace = container.getTrace();
		Map<String, String> headers = (HashMap<String, String>) globalContainer.getParameter("headers");
		
		// iterate through the Hashmap and load the key-value sets into dynamic parameters
		for(Map.Entry<String, String> helement : headers.entrySet()) {
			String keyVal = (String)helement.getKey();
			try {
				DynamicConfiguration conf1 = (DynamicConfiguration) container.getTransformationParameters().get(StreamTransformationConstants.DYNAMIC_CONFIGURATION);
				DynamicConfigurationKey key1 = DynamicConfigurationKey.create("http://sap.com/xi/XI/System/REST",keyVal);
				String elemVal = (String)helement.getValue();
				conf1.put(key1,elemVal);
				trace.addInfo("Key: " + keyVal + "Value: " + elemVal + "\n");
				loadAuditMessage(("Key: " + keyVal + "Value: " + elemVal + "\n"), container);
			} catch(Exception e) {
				trace.addInfo("Unable to add key as dynamic param: " + keyVal);
			}
		}
		return null;
	}

	@LibraryMethod(title="getDynamicParameters", description="", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String getDynamicParameters (
		@Argument(title="")  String key,
		 Container container)  throws StreamTransformationException{
			String value = "";
	try {
				DynamicConfiguration conf1 = (DynamicConfiguration) container.getTransformationParameters().get(StreamTransformationConstants.DYNAMIC_CONFIGURATION);
				DynamicConfigurationKey key1 = DynamicConfigurationKey.create("http://sap.com/xi/XI/System/File",key);
				value = "" + conf1.get(key1);
			} catch(Exception e) {
			}
return value;
	}

	@LibraryMethod(title="calculateAWSSignature", description="Calculate values for AWS signature and assign them as headers", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String calculateAWSSignature (
		@Argument(title="Content - Payload")  String content,
		@Argument(title="AWS Access Key")  String awsAccessKey,
		@Argument(title="AWS Secret Key")  String awsSecretKey,
		@Argument(title="Bucket")  String bucket,
		@Argument(title="Region")  String region,
		@Argument(title="Date")  String date,
		@Argument(title="Time")  String time,
		@Argument(title="Action")  String action,
		 Container container)  throws StreamTransformationException{
			//global declarations
        AbstractTrace trace;
        String fileName = "";
    		String tempcontent = "";
        String contenthash = "";
        GlobalContainer globalContainer = container.getGlobalContainer();
        Map<String, String> headers = new HashMap<String, String>();
        Map<String, String> mpuData = new HashMap<String, String>();

        //initialize variables
        trace = container.getTrace();
        globalContainer.setParameter("headers", headers);
        globalContainer.setParameter("mpuData", mpuData);
        
        //init
        trace.addInfo("AWS Signature Calculation begins");
        
        // read the attachment
        /*InputAttachments inputAttachments = globalContainer.getInputAttachments();
        try
        {
            if(inputAttachments.areAttachmentsAvailable()){
                trace.addInfo("Attachments found");
                // make a collection of all files found - usually one,
                // but we have to cover edge cases as well
                Collection <String> CollectionIDs = inputAttachments.getAllContentIds(true);
                Object[] arrayObj = CollectionIDs.toArray();
                // loop at every attachment to get the content
                for(int i = 0; i < arrayObj.length; i++){
                    String attachmentID = (String) arrayObj[i];
                    //***call filename to dynamic parameter function here
                    // get file contents
                    Attachment attachment = inputAttachments.getAttachment(attachmentID);
                    content = content + new String(attachment.getContent());
                    // get file name for further processing
                    attachmentName = extractFileName(attachment.getContentType(), container); // To implement - extract file name
                }
            }
            trace.addInfo("Content:" + content);
            trace.addInfo("FileName:" + attachmentName);
        } catch(Exception e){
            trace.addInfo("Unable to extract attachment information");
        } // end catch block */
        
        // get file name
        /* DynamicConfiguration conf1 = (DynamicConfiguration) container.getTransformationParameters().get(StreamTransformationConstants.DYNAMIC_CONFIGURATION);
        DynamicConfigurationKey key1 = DynamicConfigurationKey.create( "http:/"+"/sap.com/xi/XI/System/File","FileName");

        fileName = conf1.get(key1);
        conf1.put(key1,fileName); */

        fileName = getDynamicParameters("FileName", container);
				headers.put("1_"+"fileName", fileName);
			String tempFilename = fileName;
        //loadAuditMessage(("Content: " + content), container);	
		loadAuditMessage(("FileName: " + fileName), container);
		loadAuditMessage(("Action: " + action), container);
		tempcontent = content;
		if(action.contains("MULTIPART_UPLOAD")) {
			String tempdata = getMetadataFileContents(container);
			if(fileName.contains("99999999")) {
				tempcontent = formCompleteMPUContent(container);
			}	else if(fileName.contains("00000000")) {
				tempcontent = "";
			}
		}
       // loadAuditMessage(("Content: " + tempcontent), container);
        // load payload related values into map
        if (!(fileName.equals(null)) && !(fileName.equals(""))){
        	defineReqParameters(fileName, action, container);
        	if(fileName.contains("company-multi")) {
        		fileName = "company-multi.csv";
        	} else if(fileName.contains("company-single")) {
        		fileName = "company-single.csv";
        	}
        	headers.put("1_"+"attachmentName", fileName);
        	headers.put("0_"+"content_length", String.valueOf(tempcontent.length()));
            contenthash = calculateHash(tempcontent, container);
            headers.put("0_"+"x_amz_content_sha256", contenthash);
        }
        
        // get date time stamp
			String dateTimeStamp = convertDateTimeStamp(date, time, container);
        headers.put("0_"+"x_amz_date", dateTimeStamp);
        
        //calculate host values
        headers.put("0_"+"host", calculateHostValue(bucket,region, container) );
        
        // storage class dynamic parameter
        //headers.put("0_"+"x_amz_storage_class", "REDUCED_REDUNDANCY");
        String queryParameters = readHashMapValuewithKey("1_QueryParams",container);
        // calculate AWS signature
        headers.put("1_"+"Authorization", computeSignature(contenthash, 
        												   awsAccessKey, 
        												   awsSecretKey, 
        												   bucket, 
        												   region, 
        												   fileName,
        												   dateTimeStamp.substring(0,8),
        												   queryParameters,
        												   container));
        
        String dynamicParams = loadDynamicParameters(container);
        if(action.contains("MULTIPART_UPLOAD")) {	// Last file for the sequence - Complete Multipart Upload 
			 		if(tempFilename.contains("99999999")){
									loadAuditMessage(("content: " + tempcontent), container);
					//					tempcontent = "";
		//			} else if(fileName.contains("00000000")){
		//								tempcontent = null;
					}
		}
			//loadAuditMessage(("tempContent: " + tempcontent), container);
        return tempcontent;
	}

	@LibraryMethod(title="extractFileName", description="Parse file name from the content type parameter", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String extractFileName (
		@Argument(title="contentType")  String contentType,
		 Container container)  throws StreamTransformationException{
			int filenameindex = -1;
		String filename = null;
		String [] contentTypeValues = contentType.split(";");
		
		for(int i = 0; i < contentTypeValues.length && contentTypeValues[i].contains("filename");) {
			filenameindex = i;
			break;
		}
		if (filenameindex >= 0) {
			String tempval = contentTypeValues[filenameindex];
			String [] filenameKeyValuePair = tempval.split("=");
			if(filenameKeyValuePair.length > 0) {
				filename = filenameKeyValuePair[filenameKeyValuePair.length - 1];
				filename.replace("\"", null);	// remove double quotes surrounding the file name
			}
		}
		return filename;
	}

	@LibraryMethod(title="calculateHash", description="Calculate hex(HMAC(content))", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String calculateHash (
		@Argument(title="Payload Content")  String content,
		 Container container)  throws StreamTransformationException{
			AbstractTrace trace = container.getTrace();
		
			try {
				java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
				md.update(content.getBytes("UTF-8"));
				String message = "Content in bytes: " + (content.getBytes("UTF-8")).toString();
				loadAuditMessage(message, container);
				byte[] byteData=md.digest();
				StringBuilder byteContent = new StringBuilder();
				for (byte b : byteData) {
					byteContent.append(String.format("%02x", b));
				}
				content = byteContent.toString();
				//converting to hex
				//content = toHex(content, container);
			} catch( Exception e ) {
				loadAuditMessage("Unable to calculate payload hash", container);	
				trace.addInfo("Unable to calculate payload hash");
			}
			loadAuditMessage(("Content Hash: " + content), container);
			trace.addInfo("Content Hash: " + content);
			return content;
	}

	@LibraryMethod(title="convertDateTimeStamp", description="Convert given date and time to ISO-8601 format", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String convertDateTimeStamp (
		@Argument(title="Current Date")  String date,
		@Argument(title="Current Time")  String time,
		 Container container)  throws StreamTransformationException{
			AbstractTrace trace = container.getTrace();
		String fromTZ = "Australia/Melbourne";
        String toTZ = "UTC";
        String format = "yyyyMMdd\'T\'HHmmss'"; // Date Time format expected: yyyyMMdd'T'HHmmss'Z'
        
        DateTimeFormatter formatter = DateTimeFormat.forPattern(format);
        DateTimeZone originalTZ = DateTimeZone.forID(fromTZ);
        DateTime fromDateTime = new DateTime(DateTime.parse((date + "T" + time), formatter), originalTZ);
        DateTime toDateTime = fromDateTime.withZone(DateTimeZone.forID(toTZ));
        trace.addInfo("Date Time formatted: " + formatter.print(toDateTime));
        String output = formatter.print(toDateTime) + "Z";
        loadAuditMessage(("DateTimeStamp: " + output), container);
        return output;
	}

	@LibraryMethod(title="calculateHostValue", description="Find host based on parameters", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String calculateHostValue (
		@Argument(title="")  String bucket,
		@Argument(title="")  String region,
		 Container container)  throws StreamTransformationException{
			AbstractTrace trace = container.getTrace();
			String host = bucket + ".s3." + region + ".amazonaws.com";
			trace.addInfo("Host: " + host);
			loadAuditMessage(("Host: " + host), container);
			return host;
	}

	@LibraryMethod(title="formSignedHeaders", description="Form Signed Headers section", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String formSignedHeaders (
		@Argument(title="Initial Signed Header string")  String signedHeaders,
		 Container container)  throws StreamTransformationException{
			GlobalContainer globalContainer = container.getGlobalContainer();
		@SuppressWarnings("unchecked")
		Map<String, String> headers = (HashMap<String, String>) globalContainer.getParameter("headers");
		List<String> sortedHeaders = new ArrayList<String>();
		sortedHeaders.addAll(headers.keySet());
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER);
        
        //StringBuilder buffer = new StringBuilder();
        for (String header : sortedHeaders) {
        	if(header.contains("0_")) {
        		header = header.substring(2);
        		signedHeaders = signedHeaders + header + ";";
        	}
        }
        
		if(signedHeaders.endsWith(";")) {
			signedHeaders = signedHeaders.substring(0, (signedHeaders.length() - 1));
		}
		signedHeaders = signedHeaders.replaceAll("_", "-");
		return signedHeaders;
	}

	@LibraryMethod(title="formCanonicalHeaders", description="Form Canonical Header", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String formCanonicalHeaders (
		 Container container)  throws StreamTransformationException{
			GlobalContainer globalContainer = container.getGlobalContainer();
		@SuppressWarnings("unchecked")
		
		Map<String, String> headers = (HashMap<String, String>) globalContainer.getParameter("headers");
		String canonicalHeaders="";
		Map<String, String> treeMap = new TreeMap(headers);
		AbstractTrace trace = container.getTrace();

		for(Map.Entry<String, String> helement : treeMap.entrySet()) {
			String keyVal = (String)helement.getKey();
			if(keyVal.contains("0_")) {
				String elemVal = (String)helement.getValue();
				canonicalHeaders = canonicalHeaders + 
								   (keyVal.substring(2)).toLowerCase().replaceAll("\\s+", " ") + 
								   ":" + 
								   elemVal.trim().replaceAll("\\s+", " ") + 
								   "\n";
			}
		}
		
		if(canonicalHeaders.endsWith(";")) {
			canonicalHeaders = canonicalHeaders.substring(0, (canonicalHeaders.length() - 2));
		}
		canonicalHeaders = canonicalHeaders.replaceAll("_", "-");
		canonicalHeaders = canonicalHeaders.replaceAll("REDUCED-REDUNDANCY", "REDUCED_REDUNDANCY");
		trace.addInfo("canonicalHeaders" + canonicalHeaders);
		loadAuditMessage(("canonicalHeaders" + canonicalHeaders), container);
		return canonicalHeaders;
	}

	@LibraryMethod(title="formCanonicalRequest", description="Form Canonical Request", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String formCanonicalRequest (
		@Argument(title="URL endpoint")  String endpointURL,
		@Argument(title="HTTP Method")  String httpMethod,
		@Argument(title="Signed Header String")  String signedHeaders,
		@Argument(title="Canonical Header String")  String canonicalHeaders,
		@Argument(title="Query Parameter String")  String queryParameters,
		@Argument(title="Payload hash")  String contentHash,
		 Container container)  throws StreamTransformationException{
			AbstractTrace trace = container.getTrace();
		
			String canonicalRequest = httpMethod + "\n" +
								  getCanonicalizedResource(endpointURL, container) + "\n" +
								  queryParameters + "\n" +
								  canonicalHeaders + "\n" +
								  signedHeaders + "\n" +
								  contentHash;
			trace.addInfo("canonicalRequest: " + canonicalRequest);
			loadAuditMessage(("canonicalRequest: " + canonicalRequest), container);
			return canonicalRequest;
	}

	@LibraryMethod(title="getCanonicalizedResource", description="Canonicalised Resource from URL", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String getCanonicalizedResource (
		@Argument(title="Endpoint")  String endpointURL,
		 Container container)  throws StreamTransformationException{
			String outputString = "";
			AbstractTrace trace = container.getTrace();

		 if((endpointURL == null)||(endpointURL.equals(""))) {
			return "/";
		 }
		 else {
			 try {
				URL endpoint = new URL(endpointURL);
				String path = endpoint.getPath();
				if ( path == null || path.isEmpty() ) {
					return "/";
				}
				String encodedPath = urlEncode(path, "true", container);
				if(encodedPath.startsWith("/")) {
					return encodedPath;
				} else {
					return "/".concat(encodedPath);
				}
			 } catch(Exception e) {
			 }
		 }
		 trace.addInfo("outputString: " + outputString);
		 loadAuditMessage(("Encoded URL: " + outputString), container);
		 return outputString;
	}

	@LibraryMethod(title="urlEncode", description="Encode the URI", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String urlEncode (
		@Argument(title="URL Path")  String path,
		@Argument(title="Keep Path Slash")  String keepPathSlash,
		 Container container)  throws StreamTransformationException{
			AbstractTrace trace = container.getTrace();
		String encoded = "";
		try {
			encoded = URLEncoder.encode(path, "UTF-8");
		} catch(Exception e) {
			
		}
		if(keepPathSlash.equals("true")) {
			encoded = encoded.replace("%2F", "/");
		}
		trace.addInfo("Encoded URL: " + encoded);
		loadAuditMessage(("Encoded URL: " + encoded), container);
		return encoded;
	}

	@LibraryMethod(title="formStringToSign", description="String to sign", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String formStringToSign (
		@Argument(title="Canonical Request String")  String canonicalRequest,
		@Argument(title="Scope String")  String scope,
		 Container container)  throws StreamTransformationException{
			GlobalContainer globalContainer = container.getGlobalContainer();
		Map<String, String> headers = (HashMap<String, String>) globalContainer.getParameter("headers");		
		
		String dateTimeStamp = (String) headers.get("0_x_amz_date");
		return ("AWS4-HMAC-SHA256" + "\n" +
				dateTimeStamp  + "\n" +
				scope + "\n" +
				calculateHash(canonicalRequest, container));
	}

	@LibraryMethod(title="sign", description="Encrypt the data with the key provided using given algorithm", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String sign (
		@Argument(title="Date")  String data,
		@Argument(title="Encryption Key")  String key,
		@Argument(title="Algorithm")  String algorithm,
		 Container container)  throws StreamTransformationException{
			String charSet = "UTF-8";
		byte[] valueHash = null;
		
		try{
		     Mac hmacSHA256 = Mac.getInstance(algorithm);
		     SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(charSet), algorithm);
		     hmacSHA256.init(secretKey);
		     valueHash = hmacSHA256.doFinal(data.getBytes(charSet));
		} catch(Exception e) {
			
		}
		return new String(valueHash);
	}

	@LibraryMethod(title="toHex", description="Hex Conversion Routine", category="FL_COMP_AWS", type=ExecutionType.SINGLE_VALUE) 
	public String toHex (
		@Argument(title="Data in Bytes - Displayed as String")  String byteData,
		 Container container)  throws StreamTransformationException{
			String result = "";
		
		  byte[] byteDataInBytes = byteData.getBytes();
		  StringBuffer hexString = new StringBuffer();
	      for (int i=0;i<byteDataInBytes.length;i++) {
	      String hex=Integer.toHexString(0xff & byteDataInBytes[i]);
	        if(hex.length()==1) hexString.append('0');
	        hexString.append(hex);      
	      }
	      result=hexString.toString();
	      return result;
	}
}