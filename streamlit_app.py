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

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


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



def load_db():
    try:
        with open(db_filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}



def save_db(db):
    with open(db_filename, 'w') as f:
        json.dump(db, f)


def home():
    st.title("🔑 احراز هویت امن")
    st.info(" By Ali Jahani")


def register():
    st.title("📝 ثبت نام")
    st.caption('این بخش مربوط به ساخت شناسه کاربری هست ، با این شناسه کاربری میتوانید وارد سیستم شوید !')
    user_id = st.text_input("شناسه کاربری انتخاب کنید")

    if user_id:
        if st.button("تولید کلید خصوصی"):
            private_key, public_key = generate_key_pair()

            db = load_db()

            db[user_id] = serialize_key(public_key)

            save_db(db)

            st.success(f"ثبت نام انجام شد ، شناسه کاربری شما: {user_id}")
            st.text_area("کلید خصوصی ورود شما (آن را ذخیره کنید):", serialize_key(private_key, is_private=True), height=200)

    else:
        st.warning("لطفا حتما یک شناسه کاربری وارد کنید و اینتر کنید")


def login():
    st.title("🔓 ورود")

    user_id = st.text_input("شناسه کاربری را وارد کنید:")
    private_key_pem = st.text_area("کلید خصوصی را وارد کنید:", height=200)

    if st.button("احراز هویت"):
        db = load_db()

        if user_id in db:
            try:
                private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
                message = b"authentication_request"
                signature = private_key.sign(
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    SHA256()
                )
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

                st.session_state.user_id = user_id
                st.success("شما احراز هویت شدید :) خوش آمدید !")

            except Exception as e:
                st.error("کلید خصوصی شما معتبر نیست !کلید خصوصی را کامل کپی کنید")
                st.error(f"مشکلی وجود دارد: {e}")
        else:
            st.error("شناسه کاربری پیدا نشد ! لطفا ابتدا ثبت نام کنید")


def special():
    if 'user_id' in st.session_state:
        st.title("🌟 صفحه مخصوص")
        st.write(f"سلام ! {st.session_state.user_id}! اگه این صفحه رو میبینی یعنی با موفقیت وارد سیستم شدی:)")
    else:
        st.warning("برای دسترسی به این صفحه باید لاگین کنید")


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
