package edu.berkeley.eecs.cfc_tracker;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

/** Common process for writing data to phone DB */
public class DataUtils {
	public static void saveData(Properties data, File privateFileDir) {
		try {
			String currTimestamp = String.valueOf(System.currentTimeMillis());
			File currFile = new File(privateFileDir, currTimestamp);
			FileOutputStream outStream = new FileOutputStream(currFile);
			data.store(new FileOutputStream(currFile), "Data for "+currTimestamp);
			outStream.close();
		} catch (IOException e) {
			// TODO: Revisit error handling
			System.err.println("Caught IO Exception "+e+" while writing sensor values, dropping them");
		}
	}
	
	public static Properties readData(File dataFile) throws IOException {
		Properties props = new Properties();
		FileInputStream inStream = new FileInputStream(dataFile);
		props.load(inStream);
		return props;
	}
}
