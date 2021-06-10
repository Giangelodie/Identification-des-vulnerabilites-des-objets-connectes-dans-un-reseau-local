import pyautogui, time

pyautogui.hotkey('alt', 'tab')
pyautogui.typewrite('exit')
pyautogui.press("enter")
pyautogui.hotkey('alt', 'tab')
time.sleep(2)
pyautogui.press("enter")
