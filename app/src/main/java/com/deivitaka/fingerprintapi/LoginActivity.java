package com.deivitaka.fingerprintapi;

import android.Manifest;
import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.design.widget.Snackbar;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.app.LoaderManager.LoaderCallbacks;

import android.content.CursorLoader;
import android.content.Loader;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;

import android.os.Build;
import android.os.Bundle;
import android.provider.ContactsContract;
import android.text.TextUtils;
import android.util.Base64;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.inputmethod.EditorInfo;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static android.Manifest.permission.READ_CONTACTS;

/**
 * A login screen that offers login via email/password.
 */
public class LoginActivity extends AppCompatActivity
        implements LoaderCallbacks<Cursor>,
        FingerprintHelper.FingerprintHelperListener {

    //region Variables
    private static final int REQUEST_READ_CONTACTS = 0;

    private AutoCompleteTextView mEmailView;
    private EditText mPasswordView;
    private View mProgressView;
    private View mLoginFormView;
    private TextView mNoteTextView;

    private UserLoginTask mAuthTask;

    private static final String KEY_ALIAS = "sitepoint";
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String PREFERENCES_KEY_EMAIL = "email";
    private static final String PREFERENCES_KEY_PASS = "pass";
    private static final String PREFERENCES_KEY_IV = "iv";

    private KeyStore keyStore;
    private KeyGenerator generator;
    private Cipher cipher;
    private FingerprintManager fingerprintManager;
    private KeyguardManager keyguardManager;
    private FingerprintManager.CryptoObject cryptoObject;
    private SharedPreferences sharedPreferences;
    private FingerprintHelper fingerprintHelper;

    private boolean encrypting;
    //endregion

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        // Set up the login form.
        mEmailView = (AutoCompleteTextView) findViewById(R.id.email);
        populateAutoComplete();

        mPasswordView = (EditText) findViewById(R.id.password);
        mPasswordView.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            @Override
            public boolean onEditorAction(TextView textView, int id, KeyEvent keyEvent) {
                if (id == R.id.login || id == EditorInfo.IME_NULL) {
                    attemptRegister();
                    return true;
                }
                return false;
            }
        });

        Button mRegisterButton = (Button) findViewById(R.id.email_sign_in_button);
        mRegisterButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                attemptRegister();
            }
        });
        Button mFingerprintSignInButton = (Button) findViewById(R.id.fingerprint_sign_in_button);
        mFingerprintSignInButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                attemptFingerprintLogin();
            }
        });

        mLoginFormView = findViewById(R.id.login_form);
        mProgressView = findViewById(R.id.login_progress);

        mNoteTextView = (TextView)findViewById(R.id.noteTextView);

        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);
    }

    @Override
    protected void onPause() {
        super.onPause();

        if (fingerprintHelper != null)
            fingerprintHelper.cancel();

        if (mAuthTask != null)
            mAuthTask.cancel(true);
    }

    private void populateAutoComplete() {
        if (!mayRequestContacts()) {
            return;
        }

        getLoaderManager().initLoader(0, null, this);
    }

    private boolean mayRequestContacts() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return true;
        }
        if (checkSelfPermission(READ_CONTACTS) == PackageManager.PERMISSION_GRANTED) {
            return true;
        }
        if (shouldShowRequestPermissionRationale(READ_CONTACTS)) {
            Snackbar.make(mEmailView, R.string.permission_rationale, Snackbar.LENGTH_INDEFINITE)
                    .setAction(android.R.string.ok, new View.OnClickListener() {
                        @Override
                        @TargetApi(Build.VERSION_CODES.M)
                        public void onClick(View v) {
                            requestPermissions(new String[]{READ_CONTACTS}, REQUEST_READ_CONTACTS);
                        }
                    });
        } else {
            requestPermissions(new String[]{READ_CONTACTS}, REQUEST_READ_CONTACTS);
        }
        return false;
    }

    /**
     * Callback received when a permissions request has been completed.
     */
    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        if (requestCode == REQUEST_READ_CONTACTS) {
            if (grantResults.length == 1 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                populateAutoComplete();
            }
        }
    }


    /**
     * Attempts to sign in or register the account specified by the login form.
     * If there are form errors (invalid email, missing fields, etc.), the
     * errors are presented and no actual login attempt is made.
     */
    private void attemptRegister() {
        if (!testFingerPrintSettings())
            return;

        if (mAuthTask != null) {
            return;
        }

        // Reset errors.
        mEmailView.setError(null);
        mPasswordView.setError(null);

        // Store values at the time of the login attempt.
        String email = mEmailView.getText().toString();
        String password = mPasswordView.getText().toString();

        boolean cancel = false;
        View focusView = null;

        // Check for a valid password, if the user entered one.
        if (!TextUtils.isEmpty(password) && !isPasswordValid(password)) {
            mPasswordView.setError(getString(R.string.error_invalid_password));
            focusView = mPasswordView;
            cancel = true;
        }

        // Check for a valid email address.
        if (TextUtils.isEmpty(email)) {
            mEmailView.setError(getString(R.string.error_field_required));
            focusView = mEmailView;
            cancel = true;
        } else if (!isEmailValid(email)) {
            mEmailView.setError(getString(R.string.error_invalid_email));
            focusView = mEmailView;
            cancel = true;
        }

        if (cancel) {
            // There was an error; don't attempt login and focus the first
            // form field with an error.
            focusView.requestFocus();
        } else {
            // Show a progress spinner, and kick off a background task to
            // perform the user login attempt.
            showProgress(true);
            mAuthTask = new UserLoginTask(email, password);
            mAuthTask.execute((Void) null);
        }
    }

    private boolean isEmailValid(String email) {
        //TODO: Replace this with your own logic
        return email.contains("@");
    }

    private boolean isPasswordValid(String password) {
        //TODO: Replace this with your own logic
        return password.length() > 4;
    }

    /**
     * Shows the progress UI and hides the login form.
     */
    @TargetApi(Build.VERSION_CODES.HONEYCOMB_MR2)
    private void showProgress(final boolean show) {
        // On Honeycomb MR2 we have the ViewPropertyAnimator APIs, which allow
        // for very easy animations. If available, use these APIs to fade-in
        // the progress spinner.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB_MR2) {
            int shortAnimTime = getResources().getInteger(android.R.integer.config_shortAnimTime);

            mLoginFormView.setVisibility(show ? View.GONE : View.VISIBLE);
            mLoginFormView.animate().setDuration(shortAnimTime).alpha(
                    show ? 0 : 1).setListener(new AnimatorListenerAdapter() {
                @Override
                public void onAnimationEnd(Animator animation) {
                    mLoginFormView.setVisibility(show ? View.GONE : View.VISIBLE);
                }
            });

            mProgressView.setVisibility(show ? View.VISIBLE : View.GONE);
            mProgressView.animate().setDuration(shortAnimTime).alpha(
                    show ? 1 : 0).setListener(new AnimatorListenerAdapter() {
                @Override
                public void onAnimationEnd(Animator animation) {
                    mProgressView.setVisibility(show ? View.VISIBLE : View.GONE);
                }
            });
        } else {
            // The ViewPropertyAnimator APIs are not available, so simply show
            // and hide the relevant UI components.
            mProgressView.setVisibility(show ? View.VISIBLE : View.GONE);
            mLoginFormView.setVisibility(show ? View.GONE : View.VISIBLE);
        }
    }

    @Override
    public Loader<Cursor> onCreateLoader(int i, Bundle bundle) {
        return new CursorLoader(this,
                // Retrieve data rows for the device user's 'profile' contact.
                Uri.withAppendedPath(ContactsContract.Profile.CONTENT_URI,
                        ContactsContract.Contacts.Data.CONTENT_DIRECTORY), ProfileQuery.PROJECTION,

                // Select only email addresses.
                ContactsContract.Contacts.Data.MIMETYPE +
                        " = ?", new String[]{ContactsContract.CommonDataKinds.Email
                .CONTENT_ITEM_TYPE},

                // Show primary email addresses first. Note that there won't be
                // a primary email address if the user hasn't specified one.
                ContactsContract.Contacts.Data.IS_PRIMARY + " DESC");
    }

    @Override
    public void onLoadFinished(Loader<Cursor> cursorLoader, Cursor cursor) {
        List<String> emails = new ArrayList<>();
        cursor.moveToFirst();
        while (!cursor.isAfterLast()) {
            emails.add(cursor.getString(ProfileQuery.ADDRESS));
            cursor.moveToNext();
        }

        addEmailsToAutoComplete(emails);
    }

    @Override
    public void onLoaderReset(Loader<Cursor> cursorLoader) {

    }

    private void addEmailsToAutoComplete(List<String> emailAddressCollection) {
        //Create adapter to tell the AutoCompleteTextView what to show in its dropdown list.
        ArrayAdapter<String> adapter =
                new ArrayAdapter<>(LoginActivity.this,
                        android.R.layout.simple_dropdown_item_1line, emailAddressCollection);

        mEmailView.setAdapter(adapter);
    }

    @Override
    public void authenticationFailed(String error) {
        print(error);
    }

    @TargetApi(Build.VERSION_CODES.M)
    @Override
    public void authenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        print("Authentication succeeded!");
        cipher = result.getCryptoObject().getCipher();

        if (encrypting) {
            String textToEncrypt = mPasswordView.getText().toString();
            encryptString(textToEncrypt);
            print(R.string.register_success);

            mEmailView.setText("");
            mPasswordView.setText("");
        }
        else {
            String encryptedText = sharedPreferences.getString(PREFERENCES_KEY_PASS, "");
            decryptString(encryptedText);
            print(R.string.fingerprint_authenticate_success);
        }
    }

    public void encryptString(String initialText) {
        print("Encrypting...");
        try {
            byte[] bytes = cipher.doFinal(initialText.getBytes());
            String encryptedText = Base64.encodeToString(bytes, Base64.NO_WRAP);

            SharedPreferences.Editor editor = sharedPreferences.edit();
            editor.putString(PREFERENCES_KEY_PASS, encryptedText);
            editor.commit();

//            print(encryptedText);
        } catch (Exception e) {
            print(e.getMessage());
        }
    }

    public void decryptString(String cipherText) {
        print("Decrypting...");
        try {
            byte[] bytes = Base64.decode(cipherText, Base64.NO_WRAP);
            String finalText = new String(cipher.doFinal(bytes));
            mPasswordView.setText(finalText);
            mEmailView.setText(sharedPreferences.getString(PREFERENCES_KEY_EMAIL, ""));
        } catch (Exception e) {
            print(e.getMessage());
        }
    }

    private void attemptFingerprintLogin() {
        if (!testFingerPrintSettings())
            return;

        if (!usersRegistered())
            return;

        showProgress(true);
        mAuthTask = new UserLoginTask();
        mAuthTask.execute((Void) null);
    }

    private interface ProfileQuery {
        String[] PROJECTION = {
                ContactsContract.CommonDataKinds.Email.ADDRESS,
                ContactsContract.CommonDataKinds.Email.IS_PRIMARY,
        };

        int ADDRESS = 0;
        int IS_PRIMARY = 1;
    }

    /**
     * Represents an asynchronous login/registration task used to authenticate
     * the user.
     */
    public class UserLoginTask extends AsyncTask<Void, Void, Boolean> {

        private final String mEmail;
        private final String mPassword;
        private final Boolean mRegister; // if false, authenticate instead

        UserLoginTask(String email, String password) {
            mEmail = email;
            mPassword = password;
            mRegister = true;
            fingerprintHelper = new FingerprintHelper(LoginActivity.this);
        }

        UserLoginTask() {
            mRegister = false;
            mEmail = null;
            mPassword = null;
            fingerprintHelper = new FingerprintHelper(LoginActivity.this);
        }

        @Override
        protected Boolean doInBackground(Void... params) {
            if (!getKeyStore())
                return false;

            if (!createNewKey(false))
                return false;

            // Inside doInBackground
            if (!getCipher())
                return false;

            // Inside doInBackground
            if (mRegister) {
                SharedPreferences.Editor editor = sharedPreferences.edit();
                editor.putString(PREFERENCES_KEY_EMAIL, mEmail);
                editor.commit();

                encrypting = true;

                if (!initCipher(Cipher.ENCRYPT_MODE))
                    return false;
            }
            else {
                encrypting = false;
                if (!initCipher(Cipher.DECRYPT_MODE))
                    return false;
            }

            if (!initCryptObject())
                return false;

            return true;
        }

        @Override
        protected void onPostExecute(final Boolean success) {
            onCancelled();

            if (!success) {
                if (mRegister)
                    print(R.string.register_fail);
                else
                    print(R.string.fingerprint_authenticate_fail);
            } else {
                fingerprintHelper.startAuth(LoginActivity.this.fingerprintManager, cryptoObject);
                print("Authenticate using fingerprint!");
            }
        }

        @Override
        protected void onCancelled() {
            mAuthTask = null;
            showProgress(false);
        }
    }

    public void print(String text) {
        mNoteTextView.setText(text + "\n" + mNoteTextView.getText());
    }

    public void print(int id) {
        print(getString(id));
    }

    @SuppressLint("NewApi")
    private boolean testFingerPrintSettings() {
        print("Testing Fingerprint Settings");

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M)
        {
            print("This Android version does not support fingerprint authentication.");
            return false;
        }

        keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            if (!keyguardManager.isKeyguardSecure()) {
                print("User hasn't enabled Lock Screen");
                return false;
            }
        }

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            print("User hasn't granted permission to use Fingerprint");
            return false;
        }

        if (!fingerprintManager.hasEnrolledFingerprints()) {
            print("User hasn't registered any fingerprints");
            return false;
        }

        print("Fingerprint authentication is set.\n");

        return true;
    }

    private boolean usersRegistered() {
        if (sharedPreferences.getString(PREFERENCES_KEY_EMAIL, null) == null) {
            print("No user is registered");
            return false;
        }

        return true;
    }

    private boolean getKeyStore() {
        print("Getting keystore...");
        try {
            keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null); // Create empty keystore
            return true;
        } catch (KeyStoreException e) {
            print(e.getMessage());
        } catch (CertificateException e) {
            print(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            print(e.getMessage());
        } catch (IOException e) {
            print(e.getMessage());
        }

        return false;
    }

    @TargetApi(Build.VERSION_CODES.M)
    public boolean createNewKey(boolean forceCreate) {
        print("Creating new key...");
        try {
            if (forceCreate)
                keyStore.deleteEntry(KEY_ALIAS);

            if (!keyStore.containsAlias(KEY_ALIAS)) {
                generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);

                generator.init(new KeyGenParameterSpec.Builder (KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .setUserAuthenticationRequired(true)
                        .build()
                );

                generator.generateKey();
                print("Key created.");
            } else
                print("Key exists.");

            return true;
        } catch (Exception e) {
            print(e.getMessage());
        }

        return false;
    }

    private boolean getCipher() {
        print("Getting cipher...");
        try {
            cipher = Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/"
                            + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7);

            return true;
        } catch (NoSuchAlgorithmException e) {
            print(e.getMessage());
        } catch (NoSuchPaddingException e) {
            print(e.getMessage());
        }

        return false;
    }

    @TargetApi(Build.VERSION_CODES.M)
    private boolean initCipher(int mode) {
        print("Initializing cipher...");
        try {
            keyStore.load(null);
            SecretKey keyspec = (SecretKey)keyStore.getKey(KEY_ALIAS, null);

            if (mode == Cipher.ENCRYPT_MODE) {
                cipher.init(mode, keyspec);

                SharedPreferences.Editor editor = sharedPreferences.edit();
                editor.putString(PREFERENCES_KEY_IV, Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP));
                editor.commit();
            }
            else {
                byte[] iv = Base64.decode(sharedPreferences.getString(PREFERENCES_KEY_IV, ""), Base64.NO_WRAP);
                IvParameterSpec ivspec = new IvParameterSpec(iv);
                cipher.init(mode, keyspec, ivspec);
            }

            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            print(e.getMessage());
            createNewKey(true); // Retry after clearing entry
        } catch (Exception e) {
            print(e.getMessage());
        }

        return false;
    }

    @TargetApi(Build.VERSION_CODES.M)
    private boolean initCryptObject() {
        print("Initializing crypt object...");
        try {
            cryptoObject = new FingerprintManager.CryptoObject(cipher);
            return true;
        } catch (Exception ex) {
            print(ex.getMessage());
        }
        return false;
    }
}

