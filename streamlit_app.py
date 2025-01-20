import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
import json
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,500&family=Noto+Sans+Arabic:wght@500&display=swap');
html{direction: rtl}
.st-emotion-cache-1fttcpj , .st-emotion-cache-nwtri{display:none;}
.st-emotion-cache-5rimss p{text-align:right;font-family: 'DM Sans', sans-serif;
font-family: 'Noto Sans Arabic', sans-serif;
}
h1,h2,h3,h4,h5,h6{font-family: 'Noto Sans Arabic', sans-serif;}
span,p,a,button,ol,li {text-align:right;font-family: 'DM Sans', sans-serif;
font-family: 'Noto Sans Arabic', sans-serif;
}
</style>
""", unsafe_allow_html=True)

# فایل JSON برای ذخیره‌سازی داده‌ها
db_filename = 'users.json'


# Helper function to generate keys
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


# Helper function to serialize keys
def serialize_key(key, is_private=False):
    if is_private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()


# Helper function to load the database from JSON file
def load_db():
    try:
        with open(db_filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


# Helper function to save the database to JSON file
def save_db(db):
    with open(db_filename, 'w') as f:
        json.dump(db, f)


# Home page
def home():
    st.title("🔑 احراز هویت امن")
    st.info(" By Ali Jahani")


# Registration page
def register():
    st.title("📝 ثبت نام")
    st.caption('این بخش مربوط به ساخت شناسه کاربری هست ، با این شناسه کاربری میتوانید وارد سیستم شوید !')
    user_id = st.text_input("شناسه کاربری انتخاب کنید")

    if user_id:
        if st.button("تولید کلید خصوصی"):
            private_key, public_key = generate_key_pair()

            # Load existing database or create new one
            db = load_db()

            # Save public key to the database
            db[user_id] = serialize_key(public_key)

            # Save the updated database to JSON file
            save_db(db)

            st.success(f"ثبت نام انجام شد ، شناسه کاربری شما: {user_id}")
            # st.text_area("کلید عمومی برای سرور :", db[user_id], height=200)
            st.text_area("کلید خصوصی ورود شما (آن را ذخیره کنید):", serialize_key(private_key, is_private=True), height=200)

    else:
        st.warning("لطفا حتما یک شناسه کاربری وارد کنید و اینتر کنید")


# Login page
def login():
    st.title("🔓 ورود")

    user_id = st.text_input("شناسه کاربری را وارد کنید:")
    private_key_pem = st.text_area("کلید خصوصی را وارد کنید:", height=200)

    if st.button("احراز هویت"):
        # Load the database from JSON file
        db = load_db()

        if user_id in db:
            try:
                # Load private key
                private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)

                # Generate a temporary message for authentication
                message = b"authentication_request"
                signature = private_key.sign(
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    SHA256()
                )

                # Verify the signature with the stored public key
                stored_public_key = serialization.load_pem_public_key(db[user_id].encode())
                stored_public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    SHA256()
                )

                # Store user ID in session state to indicate successful login
                st.session_state.user_id = user_id
                st.success("شما احراز هویت شدید :) خوش آمدید !")

            except Exception as e:
                st.error("Authentication failed. Ensure your private key is correct.")
                st.error(f"Error: {e}")
        else:
            st.error("شناسه کاربری پیدا نشد ! لطفا ابتدا ثبت نام کنید")


# Special page for logged-in users
def special():
    if 'user_id' in st.session_state:
        st.title("🌟 Special Page")
        st.write(f"Hello {st.session_state.user_id}! This program is only available to registered users.")
    else:
        st.warning("You must be logged in to access this page.")


# Main app
def main():
    st.sidebar.title("منو")
    options = [ "ثبت نام", "ورود"]
    if 'user_id' in st.session_state:
        options.append("Special")  # Show "Special" option only if the user is logged in
    choice = st.sidebar.radio("", options)

    if choice == "ثبت نام":
        register()
    elif choice == "ورود":
        login()
    elif choice == "Special":
        special()


if __name__ == "__main__":
    main()
