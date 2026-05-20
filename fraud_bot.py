import os
import asyncio
import logging
from io import BytesIO
from PIL import Image
try:
    import cv2
    import numpy as np
    QR_ENABLED = True
except Exception as e:
    QR_ENABLED = False
    print(f"Warning: QR scanning disabled (missing cv2 or numpy): {e}")
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.ext import Application, MessageHandler, filters, ContextTypes
from dotenv import load_dotenv

from src.config import load_config
from src.agents import ThreatDetectionAgent, IncidentResponseAgent

# Load environment variables
# CRITICAL FIX: override=True forces Python to use the .env file 
# instead of any old keys stuck in the Powershell terminal's memory.
load_dotenv(override=True)
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
os.environ["GROQ_API_KEY"] = os.getenv("GROQ_API_KEY", "")

# Setup logging
logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Config & Agents once
config = load_config()
threat_agent = ThreatDetectionAgent(config)
ir_agent = IncidentResponseAgent(config)

# ==============================================================================
# AGENT 1: DETECTION (Rule-Based + Keyword Signals)
# No AI is used here. This is pure pattern matching and QR code extraction.
# ==============================================================================
def agent1_detection(text: str, qr_data: str = None) -> dict:
    """
    Detects known threat signals using rule-based keywords.
    """
    signals = []
    text_lower = text.lower()
    
    # Simple Rule-Based Checks
    if "otp" in text_lower:
        signals.append("OTP requested/shared")
    if "cbi" in text_lower or "digital arrest" in text_lower or "police" in text_lower:
        signals.append("Government/Police impersonation pattern")
    if "bit.ly" in text_lower or "http" in text_lower:
        signals.append("URL detected (possible phishing)")
    if qr_data:
        signals.append(f"QR Code Payload: {qr_data}")
        
    return {
        "raw_text": text,
        "extracted_signals": signals,
        "has_signals": len(signals) > 0
    }

async def extract_qr_content(photo_file) -> str:
    """
    The user sends the QR as an image, we extract its content using cv2.
    We do NOT scan any live camera.
    """
    if not QR_ENABLED:
        logger.error("QR Code scanning is disabled due to missing system dependencies.")
        return None
        
    try:
        # Download file to memory
        byte_array = await photo_file.download_as_bytearray()
        
        # Convert to numpy array for cv2
        nparr = np.frombuffer(byte_array, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        # Decode QR
        detector = cv2.QRCodeDetector()
        data, bbox, straight_qrcode = detector.detectAndDecode(img)
        
        if data:
            return data
    except Exception as e:
        logger.error(f"QR extraction error: {e}")
        # ── FALLBACK: If QR reading fails
        pass
    return None

# ==============================================================================
# AGENT 2: INTELLIGENCE (LLM Context)
# Uses the existing ThreatDetectionAgent to understand context and severity.
# ==============================================================================
async def agent2_intelligence(detection_data: dict) -> dict:
    """
    Passes detection signals to Threat Detection Agent for contextual analysis.
    """
    prompt = f"""
    Analyze the following forwarded message for digital fraud in India.
    Raw Text: {detection_data['raw_text']}
    Signals Detected by Agent 1: {', '.join(detection_data['extracted_signals'])}
    
    Determine:
    1. Threat Type (e.g. Vishing, Impersonation, Phishing)
    2. Severity (CRITICAL, HIGH, MEDIUM, LOW)
    3. Brief explanation
    Keep it very concise.
    """
    try:
        response = await threat_agent.process(prompt)
        
        # Check if the base agent caught an API error
        if "An error occurred" in response.content:
            logger.error(f"Agent 2 API Error intercepted: {response.content}")
            return {
                "analysis": "⚠️ AI Analysis Offline (Invalid API Key).\nBasic Scan Result: Suspicious activity detected based on keywords.",
                "success": False
            }
            
        return {
            "analysis": response.content,
            "success": True
        }
    except Exception as e:
        logger.error(f"Agent 2 Intelligence failed: {e}")
        # ── FALLBACK: If AI intelligence fails completely
        return {
            "analysis": "⚠️ Unable to fully confirm safety.\nAdvice:\n• Avoid clicking unknown links.\n• Never share OTPs.",
            "success": False
        }

# ==============================================================================
# AGENT 3: RESPONSE (Actionable Output)
# Uses the existing IncidentResponseAgent to generate playbooks and helplines.
# ==============================================================================
async def agent3_response(intelligence_data: dict, detection_data: dict) -> str:
    """
    Passes intelligence to Incident Response Agent to generate user guidance.
    """
    if not intelligence_data["success"]:
        # ── FALLBACK: If Intelligence failed, provide a clean fallback response.
        return (
            "🚨 **SECURITY ALERT** 🚨\n\n"
            "We detected suspicious signals in your message, but the AI Analysis Engine is currently offline (Invalid API Key).\n\n"
            "**Immediate Advice:**\n"
            "• Do NOT click any links.\n"
            "• Do NOT share your OTP or personal details.\n"
            "• If this is a government/police impersonation, it is likely a scam.\n\n"
            "*(Admin: Please update the GROQ_API_KEY in the .env file for full AI analysis)*"
        )
        
    prompt = f"""
    Based on the following threat analysis:
    {intelligence_data['analysis']}
    
    Write a professional 'Security Report Card' message to the victim.
    Use Markdown to create a high-end UI look.
    
    Follow this exact structure:
    1. Heading: Use a prominent bold heading with emojis (e.g. *🚨 THREAT INTERCEPTED* or *✅ MESSAGE SECURE*).
    2. Separator Line: Add a separator line like `━━━━━━━━━━━━━━━━━━━━`.
    3. Explanation Section: 
       - Start with *🔍 What we found:*
       - Use a blockquote (starting with >) to explain the threat in 1-2 simple sentences.
    4. Action Section:
       - Start with *🛡️ Your Safety Steps:*
       - Provide 2-3 bullet points with friendly instructions.
    5. Footer: Add another separator line `━━━━━━━━━━━━━━━━━━━━`.
    
    Rules:
    - Use *bold* for key terms.
    - Keep it concise and clean.
    - Do NOT use code blocks (```).
    - Language Priority: 
      - If the user sends a message in **English**, reply in professional, warm English.
      - If the user sends a message in **Kannada**, reply in perfect, friendly Kannada.
      - ALWAYS match the user's input language exactly so they understand you perfectly.
    
    Raw text: {detection_data['raw_text']}
    """
    try:
        response = await ir_agent.process(prompt)
        
        if "An error occurred" in response.content:
             return "⚠️ AI Response Engine offline (Invalid API Key). Please do not engage with the suspicious message and report to 1930."
             
        return response.content
    except Exception as e:
        logger.error(f"Agent 3 Response failed: {e}")
        # ── FALLBACK: If Response agent fails
        return "⚠️ Error generating response. Please report suspicious activity to 1930 or cybercrime.gov.in."

# ==============================================================================
# TELEGRAM BOT HANDLERS
# ==============================================================================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = (
        "🛡️ **Digital Fraud Protection System**\n\n"
        "Forward any suspicious message, link, or QR code image to me. "
        "My 3-Agent system will analyze it instantly.\n\n"
        "Type /help to get a guide on how to spot digital fraud."
    )
    await update.message.reply_text(welcome_text, parse_mode="Markdown")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "📊 **How to Identify Digital Fraud**\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Scammers often use 'Social Engineering' to trick you. Look for these **Red Flags**:\n\n"
        "1️⃣ **False Urgency**: 'Account blocked tonight', 'Payment required in 2 hours'.\n"
        "2️⃣ **Unusual Links**: Look for shortened URLs like bit.ly, tinyurl, or mispelled names (e.g., sbi-verify.net).\n"
        "3️⃣ **OTP/PIN Requests**: No bank or government agency will ever ask for your OTP or UPI PIN to *receive* money.\n"
        "4️⃣ **Impersonation**: Calls or messages from 'Police', 'CBI', or 'Customs' via WhatsApp are ALWAYS fake.\n\n"
        "🛡️ **How to use this Bot:**\n"
        "• **Forward Messages**: Send any SMS or chat message here.\n"
        "• **Send Screenshots**: Upload images of suspicious QR codes or apps.\n"
        "• **Real-time Scan**: Our AI Agents will give you a security verdict instantly.\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "📞 **Emergency**: Call **1930** immediately if you have shared financial details."
    )
    await update.message.reply_text(help_text, parse_mode="Markdown")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    text = message.text or message.caption or ""
    text_clean = text.lower().strip()
    
    # 1. Quick Greeting Check
    greetings = ["hi", "hello", "hey", "hai", "good morning", "good evening", "namaste"]
    if text_clean in greetings:
        await message.reply_text(f"Hello! 🛡️ I am your Fraud Protection Agent. \n\nPlease forward any suspicious message or link to me, and I will analyze it for you.")
        return

    # 2. Silently check for signals if it's JUST text (no photo)
    if not message.photo:
        detection_data = agent1_detection(text)
        if not detection_data["has_signals"] and len(text_clean) < 15:
            await message.reply_text("I'm listening! Please forward a suspicious message or link if you want me to scan it for fraud.")
            return

    # ── ANIMATED PROCESSING STARTS (Only for potential threats) ──
    processing_msg = await message.reply_text("🔍 [1/3] Scanning for immediate threat signals...")
    await asyncio.sleep(0.8)
    
    qr_data = None
    if message.photo:
        await processing_msg.edit_text("🖼️ Extracting data from image/QR code...")
        photo_file = await context.bot.get_file(message.photo[-1].file_id)
        qr_data = await extract_qr_content(photo_file)
        if qr_data:
            text += f" [QR Code Content: {qr_data}]"
        await asyncio.sleep(0.5)
    
    if not text.strip() and not qr_data:
        await processing_msg.edit_text("❌ Please forward a text message or a QR code image.")
        return

    # 1. Detection (Update with QR data if any)
    await processing_msg.edit_text("🧠 [2/3] Analyzing intent with AI Intelligence Agent...")
    detection_data = agent1_detection(text, qr_data)
    
    # 2. Intelligence
    intelligence_data = await agent2_intelligence(detection_data)
    await asyncio.sleep(0.8)
    
    # 3. Response
    await processing_msg.edit_text("🛡️ [3/3] Generating your personalized safety guide...")
    final_response = await agent3_response(intelligence_data, detection_data)
    await asyncio.sleep(0.5)
    
    # ── ANIMATED PROCESSING ENDS ──

    # Add UI Buttons
    keyboard = [
        [InlineKeyboardButton("🌐 Report on Cybercrime Portal", url="https://cybercrime.gov.in")],
        [InlineKeyboardButton("🛡️ Learn More About Fraud", url="https://cybercrime.gov.in/Webform/Crime_OnlineCyberTrafficking.aspx")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    try:
        await processing_msg.edit_text(
            final_response,
            parse_mode="Markdown",
            reply_markup=reply_markup
        )
    except Exception as e:
        logger.error(f"Markdown parsing failed, sending raw: {e}")
        # Fallback if the LLM generates invalid markdown
        await processing_msg.edit_text(final_response, reply_markup=reply_markup)

    # 4. Silent Background Logging to Admin Dashboard
    try:
        import requests
        import re
        
        # Simple Language Detection
        lang_code = "EN"
        if re.search(r'[\u0C80-\u0CFF]', text): lang_code = "KA"   # Kannada
        elif re.search(r'[\u0900-\u097F]', text): lang_code = "HI" # Hindi
        elif re.search(r'[\u0C00-\u0C7F]', text): lang_code = "TE" # Telugu
        elif re.search(r'[\u0B80-\u0BFF]', text): lang_code = "TA" # Tamil
        elif re.search(r'[\u0D00-\u0D7F]', text): lang_code = "ML" # Malayalam

        # Extract severity and threat type if possible from analysis string
        severity = "UNKNOWN"
        if "CRITICAL" in intelligence_data.get('analysis', '').upper(): severity = "CRITICAL"
        elif "HIGH" in intelligence_data.get('analysis', '').upper(): severity = "HIGH"
        elif "MEDIUM" in intelligence_data.get('analysis', '').upper(): severity = "MEDIUM"
        elif "LOW" in intelligence_data.get('analysis', '').upper(): severity = "LOW"
        else: severity = "SAFE"
        
        threat_type = "Scam"
        if "phishing" in intelligence_data.get('analysis', '').lower() or "phishing" in str(detection_data).lower(): threat_type = "Phishing"
        elif "vishing" in intelligence_data.get('analysis', '').lower(): threat_type = "Vishing"
        elif "impersonation" in intelligence_data.get('analysis', '').lower() or "cbi" in text.lower(): threat_type = "Impersonation"
        elif "otp" in text.lower(): threat_type = "OTP Theft"
        elif qr_data: threat_type = "Malicious QR"
        
        requests.post('http://localhost:3000/api/logs', json={
            "user_id": str(update.message.from_user.id),
            "message": text[:100], 
            "threat_type": threat_type,
            "severity": severity,
            "language": lang_code
        }, timeout=2)
    except Exception as e:
        logger.error(f"Background logging failed: {e}")

def main():
    if not TELEGRAM_BOT_TOKEN:
        print("ERROR: TELEGRAM_BOT_TOKEN not set in .env")
        return
        
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    application.add_handler(MessageHandler(filters.Command("start"), start))
    application.add_handler(MessageHandler(filters.Command("help"), help_command))
    application.add_handler(MessageHandler(filters.TEXT | filters.PHOTO, handle_message))

    print("Fraud Bot is running... Press Ctrl+C to stop.")
    application.run_polling()

if __name__ == "__main__":
    main()
