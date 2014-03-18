/**
 * Service to authenticate account information. We don't actually use this right now.
 */
package edu.berkeley.eecs.cfc_tracker.smap;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

/**
 * @author shankari
 *
 */
public class AuthenticatorService extends Service {

	private Authenticator mAuthenticator;

	public void onCreate() {
		System.out.println("AuthenticatorService.onCreate() called");
		mAuthenticator = new Authenticator(this);
	}
	
	/* (non-Javadoc)
	 * @see android.app.Service#onBind(android.content.Intent)
	 */
	@Override
	public IBinder onBind(Intent intent) {
		System.out.println("AuthenticatorService.onBind() called");
		return mAuthenticator.getIBinder();
	}
}
