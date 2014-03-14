package edu.berkeley.eecs.cfc_tracker.smap;

import android.accounts.AbstractAccountAuthenticator;

/**
 * Provides account authentication with the SMAP server.
 * This is currently a NOP, since we don't need to authenticate with the server to read the data, since it is public.
 */
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.NetworkErrorException;
import android.content.Context;
import android.os.Bundle;

/**
 * @author shankari
 *
 */
public class Authenticator extends AbstractAccountAuthenticator {

	public Authenticator(Context context) {
		super(context);
		// TODO Auto-generated constructor stub
	}

	@Override
	public Bundle addAccount(AccountAuthenticatorResponse response,
			String accountType, String authTokenType,
			String[] requiredFeatures, Bundle options)
			throws NetworkErrorException {
		System.out.println("Authenticator.addAccount() called");
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Bundle confirmCredentials(AccountAuthenticatorResponse response,
			Account account, Bundle options) throws NetworkErrorException {
		System.out.println("Authenticator.confirmCredentials() called");		
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Bundle editProperties(AccountAuthenticatorResponse response,
			String accountType) {
		// TODO Auto-generated method stub
		System.out.println("Authenticator.editProperties() called");		
		throw new UnsupportedOperationException();
	}

	@Override
	public Bundle getAuthToken(AccountAuthenticatorResponse response,
			Account account, String authTokenType, Bundle options)
			throws NetworkErrorException {
		System.out.println("Authenticator.getAuthToken() called");		
		throw new UnsupportedOperationException();
	}

	@Override
	public String getAuthTokenLabel(String authTokenType) {
		System.out.println("Authenticator.getAuthTokenLabel() called");		
		throw new UnsupportedOperationException();
	}

	@Override
	public Bundle hasFeatures(AccountAuthenticatorResponse response,
			Account account, String[] features) throws NetworkErrorException {
		System.out.println("Authenticator.hasFeatures() called");
		throw new UnsupportedOperationException();
	}

	@Override
	public Bundle updateCredentials(AccountAuthenticatorResponse response,
			Account account, String authTokenType, Bundle options)
			throws NetworkErrorException {
		System.out.println("Authenticator.updateCredentials() called");
		throw new UnsupportedOperationException();
	}

}
