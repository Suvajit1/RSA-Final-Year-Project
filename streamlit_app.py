"""
streamlit_app.py
----------------
A web application for demonstrating RSA cryptography using SageMath.

Usage:
    streamlit run streamlit_app.py

This Streamlit application provides a user-friendly graphical interface for a complete
RSA (Rivest-Shamir-Adleman) cryptographic workflow. It leverages backend SageMath
Python scripts (`rsa_keygenerator.py`, `rsa_encrypt.py`, `rsa_decrypt.py`) to
perform the core cryptographic operations.

The application allows users to:

1.  **Generate RSA Keys (Step 1):**
    *   Input: Desired bit length for the prime numbers (p and q).
    *   Action: Invokes `rsa_keygenerator.py` to generate a public/private key pair.
    *   Output: Provides download links for `public_key.csv` (containing e, n) and
              `private_key.csv` (containing d, n).

2.  **Encrypt File (Step 2):**
    *   Input: An arbitrary file to be encrypted and the `public_key.csv`.
    *   Action: Invokes `rsa_encrypt.py`. The script reads the file in binary,
              processes it in blocks using a custom padding scheme (1-byte length
              header, message chunk with random padding, 14-byte random tail),
              and encrypts each block using the public key.
    *   Output: Provides a download link for the encrypted file (typically
              `originalfilename_cipher.originalextension`), which contains one
              ciphertext integer (representing an encrypted block) per line.

3.  **Decrypt File (Step 3):**
    *   Input: An encrypted file (generated in Step 2) and the corresponding
              `private_key.csv`.
    *   Action: Invokes `rsa_decrypt.py`. The script reads the ciphertext integers,
              decrypts each block using the private key, removes the custom padding
              by interpreting the 1-byte length header, and concatenates the
              original message chunks.
    *   Output: Provides a download link for the decrypted file (typically
              `originalfilename_decrypted.originalextension`), which should be
              identical to the original input file.

4.  **Verify Decryption (Compare Files - Step 4):**
    *   Input: Two arbitrary files (e.g., the original file and the decrypted file).
    *   Action: Performs a byte-by-byte comparison of the two uploaded files directly
              within the Streamlit application.
    *   Output: Displays a success message if the files are identical, or a failure
              message along with file sizes if they differ.

The application maintains session-specific temporary directories to handle file
uploads and outputs from the SageMath scripts, ensuring user data isolation.
It provides informative messages, including the SageMath commands being run
and any output or errors from the backend scripts.
"""

import streamlit as st
import subprocess
import os
import tempfile
import uuid
import shutil

# --- Configuration ---
SAGE_EXECUTABLE = "sage"
BASE_TEMP_DIR = os.path.join(tempfile.gettempdir(), "st_rsa_app_workspace")
APP_SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))

KEYGEN_SCRIPT_NAME = "rsa_keygenerator.py"
ENCRYPT_SCRIPT_NAME = "rsa_encrypt.py"
DECRYPT_SCRIPT_NAME = "rsa_decrypt.py"

st.set_page_config(layout="wide", page_title="RSA Workflow with SageMath")

# --- Initialize Session State (Simplified - no logs) ---
if 'session_id' not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())
if 'key_gen_public_key_path' not in st.session_state:
    st.session_state.key_gen_public_key_path = None
if 'key_gen_private_key_path' not in st.session_state:
    st.session_state.key_gen_private_key_path = None
if 'encrypt_output_cipher_path' not in st.session_state:
    st.session_state.encrypt_output_cipher_path = None
if 'decrypt_output_plain_path' not in st.session_state:
    st.session_state.decrypt_output_plain_path = None

# --- Helper Functions ---
def get_session_dir():
    path = os.path.join(BASE_TEMP_DIR, st.session_state.session_id)
    os.makedirs(path, exist_ok=True)
    return path

def run_sage_script(script_name, script_args, cwd, operation_name="SageMath Script"):
    script_abs_path = os.path.join(APP_SCRIPT_DIR, script_name)
    cmd = [SAGE_EXECUTABLE, script_abs_path] + script_args
    st.info(f"Running {operation_name}: `{' '.join(cmd)}` (in directory: {cwd})") # Use st.info for user feedback
    
    try:
        process = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300) 
        stdout_clean = process.stdout.strip()
        stderr_clean = process.stderr.strip()

        if stdout_clean: 
            # For debugging, you might want to see script's stdout.
            # For user, usually only success/error messages from the script are key.
            # Example: st.text(f"{operation_name} STDOUT:\n{stdout_clean}") 
            pass
        if stderr_clean: 
            st.warning(f"{operation_name} STDERR:\n{stderr_clean}")
            
        if process.returncode == 0:
            if "Error:" in stdout_clean or "Error:" in stderr_clean:
                 st.warning(f"{operation_name} seems to have an issue despite exiting successfully. Review output if any.")
            # else:
                 # No explicit "completed successfully" log here, st.success in button handler is enough
            return True, stdout_clean, stderr_clean
        else:
            st.error(f"{operation_name} failed. Return code: {process.returncode}. Check STDERR above if any.")
            return False, stdout_clean, stderr_clean
            
    except subprocess.TimeoutExpired:
        st.error(f"{operation_name} timed out after 5 minutes.")
        return False, "", "ProcessTimedOut"
    except FileNotFoundError:
        errmsg = f"SAGE EXECUTABLE ('{SAGE_EXECUTABLE}') NOT FOUND. Ensure SageMath is installed and '{SAGE_EXECUTABLE}' is in your system's PATH."
        st.error(errmsg)
        return False, "", "SageNotFound"
    except Exception as e:
        st.error(f"An unexpected Python error occurred while running {operation_name}: {str(e)}")
        return False, "", str(e)

# --- Sidebar Content ---
st.sidebar.title("RSA Cryptography Tool")

with st.sidebar.expander("About This Application", expanded=False):
    st.markdown("""
    This web application demonstrates a complete RSA (Rivest-Shamir-Adleman) cryptographic workflow. 
    It allows you to:
    1.  **Generate** RSA public and private key pairs.
    2.  **Encrypt** messages using a public key.
    3.  **Decrypt** ciphertexts using the corresponding private key.
    4.  **Compare** text files (e.g., to verify decryption).

    All cryptographic operations are performed using SageMath scripts which are called by this Streamlit application.
    Temporary files generated during operations are stored in a session-specific directory.
    """)

with st.sidebar.expander("How to Use", expanded=False):
    st.markdown("""
    Follow these steps through the application:

    **Step 1: Generate RSA Keys**
    *   Enter a "Bit Length" for the prime numbers (p and q). Common values are 256, 512, 1024. Larger bit lengths offer stronger security but result in slower key generation and cryptographic operations.
    *   Click "Generate Keys".
    *   Once completed, download buttons for `public_key.csv` and `private_key.csv` will appear. Download these files to your system.
    *   **Important:** Keep your `private_key.csv` secure and confidential!

    **Step 2: Encrypt Message**
    *   Upload your plaintext message file (typically a `.txt` file).
    *   Upload the `public_key.csv` that you generated and downloaded in Step 1.
    *   Click "Encrypt Message".
    *   After encryption, a download button for the ciphertext file (e.g., `message_cipher.txt`) will appear. Download this encrypted file.

    **Step 3: Decrypt Message**
    *   Upload the ciphertext file (e.g., `message_cipher.txt`) obtained from Step 2.
    *   Upload the `private_key.csv` that corresponds to the public key used for the original encryption.
    *   Click "Decrypt Message".
    *   If successful, a download button for the decrypted plaintext file will become available. Download it.

    **Step 4: Compare Two Text Files**
    *   This step allows you to compare the content of any two text files.
    *   Upload the first text file (e.g., your original message).
    *   Upload the second text file (e.g., the decrypted message from Step 3).
    *   Click "Compare Files". The application will display the content of both files side-by-side and indicate whether they are identical.
    """)

# --- Main Application UI ---
st.title("RSA Key Generation, Encryption, and Decryption Workflow")
session_temp_dir = get_session_dir()

# --- 1. Key Generation ---
with st.expander("Step 1: Generate RSA Keys", expanded=True):
    bit_length_keygen = st.number_input(
        "Enter Bit Length for Primes (e.g., 256, 512, 1024):", 
        min_value=64, max_value=4096, value=512, step=64, 
        key="keygen_bits",
        help="This bit length is for p and q. The modulus n will be roughly twice this length."
    )
    
    cols_keygen_button_outer = st.columns([1,1,1]) 
    with cols_keygen_button_outer[1]:
        if st.button("Generate Keys", key="keygen_button", type="primary", use_container_width=True):
            keygen_op_dir = os.path.join(session_temp_dir, "key_generation")
            os.makedirs(keygen_op_dir, exist_ok=True)
            
            success, stdout, _ = run_sage_script(
                KEYGEN_SCRIPT_NAME, [str(bit_length_keygen)], cwd=keygen_op_dir, operation_name="RSA Key Generation"
            )
            if success and "Keys generated successfully." in stdout:
                pub_key_path = os.path.join(keygen_op_dir, "public_key.csv")
                priv_key_path = os.path.join(keygen_op_dir, "private_key.csv")
                if os.path.exists(pub_key_path) and os.path.exists(priv_key_path):
                    st.session_state.key_gen_public_key_path = pub_key_path
                    st.session_state.key_gen_private_key_path = priv_key_path
                    st.success("RSA keys generated successfully!")
                else:
                    st.error("Key files not found after generation. Check script output if any.")
                    st.session_state.key_gen_public_key_path = None
                    st.session_state.key_gen_private_key_path = None
            else:
                st.session_state.key_gen_public_key_path = None
                st.session_state.key_gen_private_key_path = None
                if success and "Keys generated successfully." not in stdout:
                     st.warning("Key generation script finished but success message not found in its output.")

    dl_col1_outer, dl_col2_outer = st.columns(2)
    with dl_col1_outer:
        dl_subcol1_center = st.columns([1,2,1])[1] 
        if st.session_state.get('key_gen_public_key_path') and os.path.exists(st.session_state.key_gen_public_key_path):
            with open(st.session_state.key_gen_public_key_path, "rb") as fp:
                dl_subcol1_center.download_button(
                    label="Download Public Key (public_key.csv)", data=fp, file_name="public_key.csv",
                    mime="text/csv", key="download_pub_key_button", type="secondary", use_container_width=True
                )
        else:
            dl_subcol1_center.empty() 
            
    with dl_col2_outer:
        dl_subcol2_center = st.columns([1,2,1])[1] 
        if st.session_state.get('key_gen_private_key_path') and os.path.exists(st.session_state.key_gen_private_key_path):
            with open(st.session_state.key_gen_private_key_path, "rb") as fp:
                dl_subcol2_center.download_button(
                    label="Download Private Key (private_key.csv)", data=fp, file_name="private_key.csv",
                    mime="text/csv", key="download_priv_key_button", type="secondary", use_container_width=True
                )
        else:
            dl_subcol2_center.empty()


# --- 2. Encryption ---
with st.expander("Step 2: Encrypt Message"):
    uploaded_message_encrypt = st.file_uploader("Upload Plaintext Message File (e.g., message.txt):", type=['txt'], key="encrypt_msg_upload")
    uploaded_public_key_encrypt = st.file_uploader("Upload Public Key File (public_key.csv from Step 1):", type=['csv'], key="encrypt_pubkey_upload")

    cols_encrypt_button_outer = st.columns([1,1,1]) 
    with cols_encrypt_button_outer[1]:
        if st.button("Encrypt Message", key="encrypt_button", type="primary", use_container_width=True):
            if uploaded_message_encrypt and uploaded_public_key_encrypt:
                encrypt_op_dir = os.path.join(session_temp_dir, "encryption")
                os.makedirs(encrypt_op_dir, exist_ok=True)
                
                message_bytes = uploaded_message_encrypt.getvalue()
                script_input_plaintext_name = "message_to_encrypt.txt" 
                with open(os.path.join(encrypt_op_dir, script_input_plaintext_name), "wb") as f: f.write(message_bytes)
                with open(os.path.join(encrypt_op_dir, "public_key_for_encrypt.csv"), "wb") as f: f.write(uploaded_public_key_encrypt.getvalue())

                success, stdout, _ = run_sage_script(
                    ENCRYPT_SCRIPT_NAME, [script_input_plaintext_name, "public_key_for_encrypt.csv"],
                    cwd=encrypt_op_dir, operation_name="RSA Encryption"
                )
                if success and "Encryption complete." in stdout:
                    output_filename_from_log = next((line.split("Encrypted file:",1)[1].strip() for line in stdout.splitlines() if "Encrypted file:" in line), None)
                    cipher_file_path = os.path.join(encrypt_op_dir, output_filename_from_log) if output_filename_from_log else os.path.join(encrypt_op_dir, f"{os.path.splitext(script_input_plaintext_name)[0]}_cipher{os.path.splitext(script_input_plaintext_name)[1]}")

                    if os.path.exists(cipher_file_path):
                        st.session_state.encrypt_output_cipher_path = cipher_file_path
                        st.success(f"Message encrypted successfully! Ciphertext file: {os.path.basename(cipher_file_path)}")
                    else:
                        st.error(f"Ciphertext file '{os.path.basename(cipher_file_path)}' not found after script execution.")
                        st.session_state.encrypt_output_cipher_path = None
                else:
                    st.session_state.encrypt_output_cipher_path = None
                    if success: st.warning("Encryption script finished but success message not found in output.")
            else:
                st.warning("Please upload both a message file and a public key file for encryption.")

    cols_enc_download_outer = st.columns([1,1,1]) 
    with cols_enc_download_outer[1]:
        if st.session_state.get('encrypt_output_cipher_path') and os.path.exists(st.session_state.encrypt_output_cipher_path):
            download_fn_enc = f"{os.path.splitext(uploaded_message_encrypt.name)[0]}_cipher{os.path.splitext(uploaded_message_encrypt.name)[1]}" if uploaded_message_encrypt else "message_cipher.txt"
            with open(st.session_state.encrypt_output_cipher_path, "rb") as fp:
                st.download_button(
                    label=f"Download Encrypted File", data=fp, file_name=download_fn_enc,
                    mime="text/plain", key="download_cipher_button", type="secondary", use_container_width=True
                )
        else:
            st.empty()


# --- 3. Decryption ---
with st.expander("Step 3: Decrypt Message"):
    uploaded_cipher_decrypt = st.file_uploader(
        "Upload Ciphertext File (e.g., message_cipher.txt):", type=None, key="decrypt_cipher_upload"
    )
    uploaded_private_key_decrypt = st.file_uploader("Upload Private Key File (private_key.csv from Step 1):", type=['csv'], key="decrypt_privkey_upload")

    cols_decrypt_button_outer = st.columns([1,1,1]) 
    with cols_decrypt_button_outer[1]:
        if st.button("Decrypt Message", key="decrypt_button", type="primary", use_container_width=True):
            if uploaded_cipher_decrypt and uploaded_private_key_decrypt:
                decrypt_op_dir = os.path.join(session_temp_dir, "decryption")
                os.makedirs(decrypt_op_dir, exist_ok=True)

                script_input_cipher_name = "cipher_to_decrypt.txt" 
                with open(os.path.join(decrypt_op_dir, script_input_cipher_name), "wb") as f: f.write(uploaded_cipher_decrypt.getvalue())
                with open(os.path.join(decrypt_op_dir, "private_key_for_decrypt.csv"), "wb") as f: f.write(uploaded_private_key_decrypt.getvalue())
                
                success, stdout, _ = run_sage_script(
                    DECRYPT_SCRIPT_NAME, [script_input_cipher_name, "private_key_for_decrypt.csv"],
                    cwd=decrypt_op_dir, operation_name="RSA Decryption"
                )
                if success and "Decryption complete." in stdout:
                    output_filename_from_log = next((line.split("Decrypted file:",1)[1].strip() for line in stdout.splitlines() if "Decrypted file:" in line), None)
                    decrypted_file_path = os.path.join(decrypt_op_dir, output_filename_from_log) if output_filename_from_log else os.path.join(decrypt_op_dir, f"{os.path.splitext(script_input_cipher_name)[0]}_decrypted{os.path.splitext(script_input_cipher_name)[1]}")

                    if os.path.exists(decrypted_file_path):
                        st.session_state.decrypt_output_plain_path = decrypted_file_path
                        st.success(f"Message decrypted successfully! Decrypted file: {os.path.basename(decrypted_file_path)}")
                    else:
                        st.error(f"Decrypted file '{os.path.basename(decrypted_file_path)}' not found after script execution.")
                        st.session_state.decrypt_output_plain_path = None
                else:
                    st.session_state.decrypt_output_plain_path = None
                    if success: st.warning("Decryption script finished but success message not found in output.")
            else:
                st.warning("Please upload both a ciphertext file and a private key file for decryption.")

    cols_dec_download_outer = st.columns([1,1,1]) 
    with cols_dec_download_outer[1]:
        if st.session_state.get('decrypt_output_plain_path') and os.path.exists(st.session_state.decrypt_output_plain_path):
            download_fn_dec = "message_decrypted.txt"
            if uploaded_cipher_decrypt and uploaded_cipher_decrypt.name:
                base_name = uploaded_cipher_decrypt.name.replace("_cipher.txt", "").replace("_cipher", "").replace(".txt","")
                original_ext = os.path.splitext(uploaded_cipher_decrypt.name)[1] if "_cipher" not in uploaded_cipher_decrypt.name else ".txt"
                download_fn_dec = f"{base_name}_decrypted{original_ext}"
            with open(st.session_state.decrypt_output_plain_path, "rb") as fp:
                st.download_button(
                    label=f"Download Decrypted File", data=fp, file_name=download_fn_dec, 
                    mime="text/plain", key="download_decrypted_button", type="secondary", use_container_width=True
                )
        else:
            st.empty()

# --- 4. Compare Uploaded Text Files ---
with st.expander("Step 4: Compare Two Text Files"):
    st.write("Upload two text files to compare their content.")

    col_upload1, col_upload2 = st.columns(2)
    with col_upload1:
        file1_compare = st.file_uploader("Upload First File:", type=['txt'], key="compare_file1_upload")
    with col_upload2:
        file2_compare = st.file_uploader("Upload Second File:", type=['txt'], key="compare_file2_upload")

    cols_compare_button_layout = st.columns([1, 1, 1])
    with cols_compare_button_layout[1]:
        compare_button_pressed = st.button("Compare Files", key="compare_files_button", type="primary", use_container_width=True)

    if compare_button_pressed:
        if file1_compare is not None and file2_compare is not None:
            content1_orig, content2_orig = "", "" # Store original content for display
            valid_read = True
            try:
                content1_orig = file1_compare.getvalue().decode('utf-8')
            except Exception as e:
                content1_orig = f"[Error reading {file1_compare.name}: {e}]"
                st.error(f"Could not read {file1_compare.name}. Ensure it's a valid UTF-8 text file.")
                valid_read = False

            try:
                content2_orig = file2_compare.getvalue().decode('utf-8')
            except Exception as e:
                content2_orig = f"[Error reading {file2_compare.name}: {e}]"
                st.error(f"Could not read {file2_compare.name}. Ensure it's a valid UTF-8 text file.")
                valid_read = False

            # Display original file contents side-by-side
            disp_col1, disp_col2 = st.columns(2)
            with disp_col1:
                st.subheader(f"Content of: {file1_compare.name}")
                st.text_area("File 1 Content", value=content1_orig, height=250, disabled=True, key="compare_text1_area_display", # Renamed key slightly
                                help="Content of the first uploaded file.")
            with disp_col2:
                st.subheader(f"Content of: {file2_compare.name}")
                st.text_area("File 2 Content", value=content2_orig, height=250, disabled=True, key="compare_text2_area_display", # Renamed key slightly
                                help="Content of the second uploaded file.")

            if valid_read:
                # --- Internal Normalization Steps ---
                content1_norm = content1_orig.replace('\r\n', '\n')
                content2_norm = content2_orig.replace('\r\n', '\n')

                lines1 = [line.rstrip() for line in content1_norm.splitlines()]
                lines2 = [line.rstrip() for line in content2_norm.splitlines()]

                content1_final_norm = "\n".join(lines1).strip()
                content2_final_norm = "\n".join(lines2).strip()
                # --- End of Internal Normalization ---

                if content1_final_norm == content2_final_norm:
                    st.success("✅ SUCCESS: The content of the two files is identical!")
                else:
                    st.error("❌ FAILURE: The content of the two files differs.")
                    
                    import difflib
                    # Generate diff based on the internally normalized content
                    diff = list(difflib.unified_diff(
                        content1_final_norm.splitlines(keepends=True),
                        content2_final_norm.splitlines(keepends=True),
                        fromfile=file1_compare.name, # Show original filenames in diff header
                        tofile=file2_compare.name,   # Show original filenames in diff header
                        lineterm='',
                    ))
                    
                    if diff:
                        st.text("Detailed Differences (highlighting subtle variations):")
                        st.code("".join(diff), language='diff')
                    else:
                        # This case should be extremely rare if the normalized strings differ
                        # but difflib finds no difference. Could indicate a bug in normalization
                        # or an extremely unusual character difference.
                        st.warning("The files are considered different, but no specific variations were highlighted by the diff tool. This might indicate very subtle, non-visible character differences.")
        else:
            st.warning("Please upload both files for comparison.")