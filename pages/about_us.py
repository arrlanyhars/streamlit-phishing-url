import streamlit as st
from PIL import Image

st.set_page_config(page_title="About Us", page_icon="🌝")

image = Image.open("image1.jpg")

st.image(image, caption="")

st.title('We are Data Wizard')
st.subheader("A coven of digital magicians creating anything wonderful from data")


st.divider()

st.write("Charisma Juni / Chacha - Data Scientist Magician")
st.write("Arryanda Maulani / Yanda - Data Engineer Magician")
st.write("Dendy Sugandi / Dendy - IT Infrastructure Magician")
st.write("M Wiwid Setiawan / Wiwid - Code Magician")
st.write("Rindang Cahyaning / Rindang - IT Consultant Magician")


