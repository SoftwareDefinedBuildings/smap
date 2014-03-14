/**
 * Creates an adapter to post data to the SMAP server
 */
package edu.berkeley.eecs.cfc_tracker.smap;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;
import java.util.Random;
import java.util.UUID;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import edu.berkeley.eecs.cfc_tracker.Constants;
import edu.berkeley.eecs.cfc_tracker.DataUtils;
import edu.berkeley.eecs.cfc_tracker.R;

import android.accounts.Account;
import android.content.AbstractThreadedSyncAdapter;
import android.content.ContentProviderClient;
import android.content.Context;
import android.content.SyncResult;
import android.net.http.AndroidHttpClient;
import android.os.Bundle;

/**
 * @author shankari
 *
 */
public class AddDataAdapter extends AbstractThreadedSyncAdapter {
	private static final String USER = "userName";
	
	private String projectName;
	private static String READINGS_NAME = "Readings"; 
	private static String SMAP_HOST = "YOUR_BMS_SERVER_HERE";
	private static String SMAP_KEY = "YOUR_BMS_KEY_HERE";
	
	private String userName;

	File privateFileDir;
	Properties uuidMap;
	// TODO: Delete after we start getting real values
	Random pseudoRandom;
	boolean syncSkip = false;
	
	public AddDataAdapter(Context context, boolean autoInitialize) {
		super(context, autoInitialize);
		privateFileDir = context.getFilesDir();
		System.out.println("AddDataAdapter constructor called with "+privateFileDir);
		// We read the project name here because that's where we have access to a context
		projectName = context.getString(R.string.app_name);
		// It's enough to initialize the uuidMap at startup, since they don't change on a regular basis
		try {
			uuidMap = getUUIDMap(privateFileDir);
		} catch (IOException e) {
			// TODO: Built in some retry logic here
			System.err.println("Unable to save uuid map to file, so no point in publishing data anyway. Skipping sync ");
			syncSkip = true;
		}
		// The username is currently a uuid, which is better for privacy, and is also easier to implement
		// because we don't have to pass data between the main activity and this adapter, AND we don't have
		// to worry about what will happen if the user forgets to sign in, etc
		
		userName = (String)uuidMap.get(USER);
		System.out.println("uuidMap.get(USER) = "+uuidMap.get(USER)+
				" userName = "+userName);

		// Create a random number generator since we don't yet have real values
		// TODO: Remove this once we get real values
		pseudoRandom = new Random();
		// Our ContentProvider is a dummy so there is nothing else to do here
	}
	
	/* (non-Javadoc)
	 * @see android.content.AbstractThreadedSyncAdapter#onPerformSync(android.accounts.Account, android.os.Bundle, java.lang.String, android.content.ContentProviderClient, android.content.SyncResult)
	 */
	@Override
	public void onPerformSync(Account account, Bundle extras, String authority,
			ContentProviderClient provider, SyncResult syncResult) {
		if (syncSkip == true) {
			System.err.println("Something is wrong and we have been asked to skip the sync, exiting immediately");
			return;
		}
		/*
		 * Get the current list of files in the directory and send them over to the server.
		 * TODO: Need to be careful about synchronization here so that we don't delete files that have not yet been sent
		 * Switch to SQLLite?
		 */
		File[] toSend = privateFileDir.listFiles(new NotUUIDFileFilter());
		System.out.println("Sending "+toSend.length+" files from "+privateFileDir);
		/* We don't really need to send the metadata every time, the first time is enough.
		 * But we don't know whether this is the first time or the nth time because the adapter
		 * is created every time. For now, send all information every time, and optimize later.
		 */
		
		/*
		 * We are going to send over information for all the data in a single JSON object, to avoid overhead.
		 * So we take a quick check to see if the number of entries is zero.
		 */
		
		if (toSend.length == 0) {
			System.out.println("No data to send, returning early!");
			return;
		}
	
		try {	
			// This is the top level object that we want to send
			JSONObject objectToSend = createTopLevelObject();
      
			// Now, we create a set of JSONArrays, one for each sensor, that we will update as we iterate over the files
			HashMap<String, JSONArray> readingArray = new HashMap<String, JSONArray>();
      
			for (int i = 0; i < Constants.sensors.length; i ++) {
				// The getPath here is to match the paths created during construction
				readingArray.put(Constants.sensors[i],
						objectToSend.getJSONObject(getPath(Constants.sensors[i])).getJSONArray(READINGS_NAME));
			}
      
			for(int i = 0; i < toSend.length; i++) {
				System.out.println("Sending data from "+toSend[i]+" via HTTP POST");
				Long timestamp = Long.valueOf(toSend[i].getName());
				try {
					Properties realData = DataUtils.readData(toSend[i]);
					Enumeration<Object> keys = realData.keys();
					while (keys.hasMoreElements()) {
						String currKey = (String)keys.nextElement();
						Double currVal = Double.valueOf(realData.getProperty(currKey));
						JSONArray currArray = new JSONArray();
						currArray.put(timestamp);
						System.out.println("Value for key = "+currKey+" = "+currVal);
						currArray.put(currVal);
						readingArray.get(currKey).put(currArray);
					}
				} catch (IOException e) {
					System.err.println("Error "+e+" while saving data for file "+toSend[i]+
							" at time "+timestamp+", skipping this sensor");
				}
				/*
				 * Commenting out the random variable generation for now.
				 * It seems like it would be useful to keep this around as a fail safe and a test mechanism,
				 * but need a way to trigger it without recompiling.
				 * Check out the unit testing framework :)
				for(int j = 0; j < Constants.sensors.length; j++) {
					// Right now, we are generating random values. Read these from the files instead.
					// Would probably be easiest if we can store them as property files because then
					// we can just read the appropriate property and don't have to do specialized parsing
					// Or maybe just switch to SQLLite, which seems like it would work pretty well for this
					try {
						double value = 100 * pseudoRandom.nextDouble();
						JSONArray currArray = new JSONArray();
						currArray.put(timestamp);
						currArray.put(value);
						readingArray.get(Constants.sensors[j]).put(currArray);
					} catch (JSONException e) {
						System.err.println("Error "+e+" while saving data for sensor "+Constants.sensors[j]+
								" at time "+timestamp+", skipping this sensor");
					}
				} */
				toSend[i].delete();
			}
			System.out.println("About to post JSON object "+objectToSend);
			addDataToSmapServer(objectToSend, SMAP_HOST);
		} catch (JSONException e) {
			System.err.println("Error "+e+" while saving data "+toSend.length+" files, skipping all of them");
		} catch (IOException e) {
			System.err.println("IO Error "+e+" while posting "+toSend.length+" files, data is LOST!");			
		}
	}

	public Properties getUUIDMap(File privateFileDir) throws FileNotFoundException, IOException {
		File uuidFile = new File(privateFileDir, "sensor-uuid.props");
		Properties uuidMap = new Properties();
		try {
			uuidMap.load(new FileInputStream(uuidFile));
		} catch (IOException e) {
			uuidMap.put(USER, UUID.randomUUID().toString());
			System.out.println("Created UUID for USER");
			for (int i = 0; i < Constants.sensors.length; i++) {
				uuidMap.put(Constants.sensors[i], UUID.randomUUID().toString());
			}
			uuidMap.store(new FileOutputStream(uuidFile), null);
		}
		return uuidMap;
	}
	
	/*
	 * We add the parts to the object for each sensor based on the order in:
	 * http://www.cs.berkeley.edu/~stevedh/smap2/archiver.html
	 * 
	 * The Metadata name recommendations are from Tyler.
	 * TODO: Check with him on whether these are special or not
	 */
	public JSONObject createTopLevelObject() throws JSONException {
		JSONObject retObject = new JSONObject();
		for (int i = 0; i < Constants.sensors.length; i++) {
			JSONObject sensorObj = new JSONObject();
			/*
			 * Note the / before the name here. That's because this name represents a path.
			 * If you remove it, this won't show up in the tree view of the sMAP server.
			 * Note also that none of the other names require this /
			 */
			retObject.put(getPath(Constants.sensors[i]), sensorObj);
			
			JSONObject metadataObj = new JSONObject();
			// All our data is for the E-Mission project
			metadataObj.put("SourceName", projectName);
			metadataObj.put("PointName", Constants.sensors[i]);
			// At this point, we don't know who the user is. Put that into settings?
			sensorObj.put("Metadata", metadataObj);
			
			JSONObject propertyObject = new JSONObject();
			propertyObject.put("Timezone", java.util.TimeZone.getDefault().getID());
			propertyObject.put("ReadingType", "double");
			sensorObj.put("Properties", propertyObject);
			
			JSONArray readings = new JSONArray();
			sensorObj.put(READINGS_NAME, readings);		
			
			sensorObj.put("uuid", uuidMap.get(Constants.sensors[i]));
		}
		System.out.println("Returning object skeleton "+retObject);
		return retObject;
	}
	
	class NotUUIDFileFilter extends Object implements FilenameFilter {
		public boolean accept(File dir, String fileName) {
			if(fileName.contains("uuid")) {
				return false;
			} else {
				return true;
			}
		}
	}
	
	public void addDataToSmapServer(JSONObject data, String smapHost)
			throws IOException {
		HttpPost msg = new HttpPost(smapHost+"/add/"+SMAP_KEY);
		System.out.println("Posting data to "+msg);
		msg.setHeader("Content-Type", "application/json");
		msg.setEntity(new StringEntity(data.toString()));
		AndroidHttpClient connection = AndroidHttpClient.newInstance(projectName);
		HttpResponse response = connection.execute(msg);
		System.out.println("Got response "+response+" with status "+response.getStatusLine());
		connection.close();
	}
	
	public String getPath(String serviceName) {
		return "/"+userName+"/"+serviceName;
	}
}
