from kivy.lang import Builder
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDFlatButton

KV = '''
BoxLayout:
    orientation: 'vertical'
    
    MDLabel:
        text: 'Welcome to KivyMD'
        halign: 'center'
        font_style: 'H4'
    
    MDFlatButton:
        text: 'Click Me'
        theme_text_color: 'Custom'
        text_color: app.theme_cls.primary_color
        pos_hint: {'center_x': 0.5}
        on_release: app.button_click()
'''


class MainApp(MDApp):
    def build(self):
        return Builder.load_string(KV)

    def button_click(self):
        print('Button clicked!')


if __name__ == '__main__':
    MainApp().run()
