import streamlit as st
from streamlit_jodit import st_jodit

st.title("Jodit Test")
jodit_config = {
    "theme": "dark", 
    "style": {"background": "#0e1117", "color": "#ffffff"}, 
    "height": 400,
    "buttons": ["source", "|", "bold", "italic", "underline", "|", "ul", "ol", "|", "paragraph", "|", "image", "table", "link", "|", "align", "undo", "redo", "|", "hr", "eraser", "fullsize"]
}
st_jodit(value="Test", config=jodit_config)
