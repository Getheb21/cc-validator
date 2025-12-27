from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import re
import sqlite3
from datetime import datetime
import os
import json

app = FastAPI(
    title="Credit Card Validator API",
    description="Professional Credit Card Validation with Luhn Algorithm",
    version="2.0"
)

# CORS untuk izinkan akses dari Cloudflare Worker
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Production: ganti dengan domain Cloudflare Worker
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
def init_db():
    conn = sqlite3.connect('card_validations.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS validations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            card_number TEXT NOT NULL,
            cleaned_number TEXT NOT NULL,
            card_type TEXT,
            is_valid BOOLEAN NOT NULL,
            luhn_total INTEGER,
            fraud_risk TEXT,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

# Pydantic Models
class ValidationRequest(BaseModel):
    card_number: str
    check_fraud: bool = True

class ValidationResponse(BaseModel):
    original: str
    cleaned: str
    card_type: str
    is_valid: bool
    luhn_total: int
    luhn_remainder: int
    fraud_risk: str
    warnings: List[str]
    formatted: str
    suggestions: List[str]
    validation_details: dict

class BatchValidationRequest(BaseModel):
    card_numbers: List[str]

class StatsResponse(BaseModel):
    total_validations: int
    valid_cards: int
    invalid_cards: int
    validity_rate: float
    by_type: dict

# Helper functions
def clean_card_number(card_number: str) -> str:
    return re.sub(r'[^\d]', '', card_number)

def luhn_check(card_number: str) -> dict:
    digits = [int(d) for d in card_number]
    total = 0
    steps = []
    
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:  # Even positions from right
            doubled = digit * 2
            if doubled >= 10:
                step_result = 1 + (doubled % 10)
            else:
                step_result = doubled
            total += step_result
        else:  # Odd positions from right
            total += digit
    
    return {
        'is_valid': total % 10 == 0,
        'total': total,
        'remainder': total % 10
    }

def identify_card_type(card_number: str) -> dict:
    CARD_TYPES = {
        'Visa': {'prefixes': ['4'], 'lengths': [13, 16, 19]},
        'MasterCard': {'prefixes': ['51', '52', '53', '54', '55', '2221-2720'], 'lengths': [16]},
        'American Express': {'prefixes': ['34', '37'], 'lengths': [15]},
        'Discover': {'prefixes': ['6011', '65', '644-649', '622126-622925'], 'lengths': [16, 19]},
        'JCB': {'prefixes': ['3528-3589'], 'lengths': [16, 17, 18, 19]},
    }
    
    cleaned = card_number
    
    for card_type, info in CARD_TYPES.items():
        for prefix in info['prefixes']:
            if '-' in prefix:
                start, end = map(int, prefix.split('-'))
                prefix_len = len(str(start))
                card_prefix = int(cleaned[:prefix_len])
                if start <= card_prefix <= end and len(cleaned) in info['lengths']:
                    return {'type': card_type, 'length_valid': True}
            elif cleaned.startswith(prefix) and len(cleaned) in info['lengths']:
                return {'type': card_type, 'length_valid': True}
    
    return {'type': 'Unknown', 'length_valid': 13 <= len(cleaned) <= 19}

def check_fraud_patterns(card_number: str) -> dict:
    warnings = []
    risk = "Low"
    
    # Check sequential
    if len(set(card_number)) == 1:
        warnings.append("All digits are the same")
        risk = "High"
    
    # Check test numbers
    test_numbers = ['4111111111111111', '4242424242424242', '5555555555554444']
    if card_number in test_numbers:
        warnings.append("Known test card number")
        risk = "Medium"
    
    return {'risk': risk, 'warnings': warnings}

def format_card_number(card_number: str, card_type: str) -> str:
    if card_type == 'American Express':
        return f"{card_number[:4]} {card_number[4:10]} {card_number[10:]}"
    else:
        return ' '.join(card_number[i:i+4] for i in range(0, len(card_number), 4))

# API Endpoints
@app.get("/")
async def root():
    return {
        "message": "Credit Card Validator API",
        "version": "2.0",
        "endpoints": {
            "GET /": "This info",
            "POST /validate": "Validate single card",
            "POST /validate/batch": "Validate multiple cards",
            "GET /stats": "Get statistics",
            "GET /examples": "Get example cards"
        }
    }

@app.post("/validate", response_model=ValidationResponse)
async def validate_card(request: ValidationRequest):
    """Validate a single credit card number"""
    
    # Clean input
    cleaned = clean_card_number(request.card_number)
    
    if not cleaned:
        raise HTTPException(status_code=400, detail="No valid digits found")
    
    if len(cleaned) < 13 or len(cleaned) > 19:
        raise HTTPException(status_code=400, detail="Invalid card length")
    
    # Identify card type
    card_info = identify_card_type(cleaned)
    
    # Luhn check
    luhn_result = luhn_check(cleaned)
    
    # Fraud check
    fraud_result = check_fraud_patterns(cleaned) if request.check_fraud else {'risk': 'Low', 'warnings': []}
    
    # Format for display
    formatted = format_card_number(cleaned, card_info['type'])
    
    # Generate suggestions
    suggestions = []
    if not luhn_result['is_valid']:
        suggestions.append("Card failed Luhn algorithm check")
    if card_info['type'] == 'Unknown':
        suggestions.append("Card type not recognized")
    
    # Save to database
    conn = sqlite3.connect('card_validations.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO validations 
        (card_number, cleaned_number, card_type, is_valid, luhn_total, fraud_risk)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        request.card_number,
        cleaned,
        card_info['type'],
        luhn_result['is_valid'],
        luhn_result['total'],
        fraud_result['risk']
    ))
    conn.commit()
    conn.close()
    
    # Prepare response
    response = ValidationResponse(
        original=request.card_number,
        cleaned=cleaned,
        card_type=card_info['type'],
        is_valid=luhn_result['is_valid'],
        luhn_total=luhn_result['total'],
        luhn_remainder=luhn_result['remainder'],
        fraud_risk=fraud_result['risk'],
        warnings=fraud_result['warnings'],
        formatted=formatted,
        suggestions=suggestions,
        validation_details={
            'length': len(cleaned),
            'iin': cleaned[:6] if len(cleaned) >= 6 else '',
            'checksum_digit': cleaned[-1] if cleaned else ''
        }
    )
    
    return response

@app.post("/validate/batch")
async def batch_validate(request: BatchValidationRequest):
    """Validate multiple card numbers at once"""
    results = []
    
    for card_number in request.card_numbers:
        try:
            # Clean input
            cleaned = clean_card_number(card_number)
            
            if not cleaned or len(cleaned) < 13 or len(cleaned) > 19:
                results.append({
                    'card_number': card_number,
                    'is_valid': False,
                    'error': 'Invalid format or length'
                })
                continue
            
            # Identify card type
            card_info = identify_card_type(cleaned)
            
            # Luhn check
            luhn_result = luhn_check(cleaned)
            
            # Format for display
            formatted = format_card_number(cleaned, card_info['type'])
            
            results.append({
                'original': card_number,
                'cleaned': cleaned,
                'formatted': formatted,
                'card_type': card_info['type'],
                'is_valid': luhn_result['is_valid'],
                'luhn_total': luhn_result['total'],
                'luhn_remainder': luhn_result['remainder']
            })
            
        except Exception as e:
            results.append({
                'card_number': card_number,
                'is_valid': False,
                'error': str(e)
            })
    
    return {
        'total_cards': len(request.card_numbers),
        'processed': len(results),
        'results': results
    }

@app.get("/stats")
async def get_stats():
    """Get validation statistics"""
    conn = sqlite3.connect('card_validations.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) as total FROM validations')
    total = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) as valid FROM validations WHERE is_valid = 1')
    valid = cursor.fetchone()[0]
    
    cursor.execute('''
        SELECT card_type, COUNT(*) as count 
        FROM validations 
        WHERE card_type IS NOT NULL 
        GROUP BY card_type
    ''')
    by_type = {row[0]: row[1] for row in cursor.fetchall()}
    
    conn.close()
    
    validity_rate = (valid / total * 100) if total > 0 else 0
    
    return StatsResponse(
        total_validations=total,
        valid_cards=valid,
        invalid_cards=total - valid,
        validity_rate=validity_rate,
        by_type=by_type
    )

@app.get("/examples")
async def get_examples():
    """Get example valid and invalid cards"""
    examples = {
        'valid_cards': [
            {
                'number': '4111111111111111',
                'type': 'Visa',
                'description': 'Test Visa card (valid)'
            },
            {
                'number': '5555555555554444',
                'type': 'MasterCard',
                'description': 'Test MasterCard (valid)'
            },
            {
                'number': '378282246310005',
                'type': 'American Express',
                'description': 'Test American Express (valid)'
            }
        ],
        'invalid_cards': [
            {
                'number': '4111111111111112',
                'type': 'Visa',
                'description': 'Invalid Visa (wrong checksum)'
            },
            {
                'number': '1234567812345678',
                'type': 'Unknown',
                'description': 'Random invalid number'
            },
            {
                'number': '1111111111111111',
                'type': 'Unknown',
                'description': 'All ones (invalid)'
            }
        ]
    }
    
    return examples

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)