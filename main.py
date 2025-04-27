from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, get_jwt,verify_jwt_in_request)
from functools import wraps
from datetime import timedelta
from passlib.hash import pbkdf2_sha256
from dotenv import load_dotenv
import os

# Загрузка переменных окружения
load_dotenv()

# Инициализация приложения
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///airline.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET', 'super-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)


# Модели данных
class Cashier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='cashier')

    def set_password(self, password):
        self.password_hash = pbkdf2_sha256.hash(password)

    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password_hash)


class Airport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    iata_code = db.Column(db.String(3), unique=True)
    icao_code = db.Column(db.String(4), unique=True)
    city = db.Column(db.String(80), nullable=False)
    country = db.Column(db.String(80), nullable=False)


class Route(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    departure_airport_id = db.Column(db.Integer, db.ForeignKey('airport.id'), nullable=False)
    arrival_airport_id = db.Column(db.Integer, db.ForeignKey('airport.id'), nullable=False)
    distance = db.Column(db.Integer)  # в км
    flight_time = db.Column(db.Integer)  # в минутах

    departure_airport = db.relationship('Airport', foreign_keys=[departure_airport_id])
    arrival_airport = db.relationship('Airport', foreign_keys=[arrival_airport_id])


class Flight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    route_id = db.Column(db.Integer, db.ForeignKey('route.id'), nullable=False)
    departure_time = db.Column(db.DateTime, nullable=False)
    arrival_time = db.Column(db.DateTime, nullable=False)
    aircraft_type = db.Column(db.String(50))
    total_seats = db.Column(db.Integer)
    available_seats = db.Column(db.Integer)
    status = db.Column(db.String(20), default='scheduled')
    base_price = db.Column(db.Float, nullable=False)

    route = db.relationship('Route')


class Passenger(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    passport_number = db.Column(db.String(20), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))


class Kassa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    location = db.Column(db.String(120))
    is_active = db.Column(db.Boolean, default=True)


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    passenger_id = db.Column(db.Integer, db.ForeignKey('passenger.id'), nullable=False)
    flight_id = db.Column(db.Integer, db.ForeignKey('flight.id'), nullable=False)
    seat_number = db.Column(db.String(10))
    seat_class = db.Column(db.String(20), default='economy')
    price = db.Column(db.Float, nullable=False)
    issue_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='issued')

    passenger = db.relationship('Passenger')
    flight = db.relationship('Flight')


class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    passenger_id = db.Column(db.Integer, db.ForeignKey('passenger.id'), nullable=False)
    flight_id = db.Column(db.Integer, db.ForeignKey('flight.id'), nullable=False)
    cashier_id = db.Column(db.Integer, db.ForeignKey('cashier.id'), nullable=False)
    reservation_date = db.Column(db.DateTime, nullable=False)
    expiry_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='active')

    passenger = db.relationship('Passenger')
    flight = db.relationship('Flight')
    cashier = db.relationship('Cashier')


class Contract(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reservation_id = db.Column(db.Integer, db.ForeignKey('reservation.id'), nullable=False)
    cashier_id = db.Column(db.Integer, db.ForeignKey('cashier.id'), nullable=False)
    contract_number = db.Column(db.String(20), unique=True, nullable=False)
    contract_date = db.Column(db.DateTime, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    contract_type = db.Column(db.String(20))

    reservation = db.relationship('Reservation')
    cashier = db.relationship('Cashier')


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer, db.ForeignKey('contract.id'), nullable=False)
    payment_date = db.Column(db.DateTime, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(20))
    status = db.Column(db.String(20), default='completed')

    contract = db.relationship('Contract')


# Вспомогательные функции
def cashier_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
            claims = get_jwt()
            if claims['role'] != 'cashier':
                return jsonify({"msg": "Cashier access required"}), 403
            return fn(*args, **kwargs)
        except Exception as e:
            return jsonify({"msg": "Access denied", "error": str(e)}), 401
    return wrapper


# API Endpoints

# 1. Аутентификация
@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    cashier = Cashier.query.filter_by(username=username).first()
    if not cashier or not cashier.check_password(password):
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(
        identity=username,
        additional_claims={'role': cashier.role, 'cashier_id': cashier.id}
    )
    return jsonify(access_token=access_token), 200


# 2. Выход
@app.route('/api/v1/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    # В реальном приложении здесь можно добавить токен в черный список
    return jsonify({"msg": "Successfully logged out"}), 200


# 3. Список аэропортов
@app.route('/api/v1/airports', methods=['GET'])
@jwt_required()
@cashier_required
def get_airports():
    airports = Airport.query.all()
    return jsonify([{
        'id': a.id,
        'name': a.name,
        'iata_code': a.iata_code,
        'icao_code': a.icao_code,
        'city': a.city,
        'country': a.country
    } for a in airports]), 200


# 4. Информация об аэропорте
@app.route('/api/v1/airports/<int:airport_id>', methods=['GET'])
@jwt_required()
@cashier_required
def get_airport(airport_id):
    airport = Airport.query.get_or_404(airport_id)
    return jsonify({
        'id': airport.id,
        'name': airport.name,
        'iata_code': airport.iata_code,
        'icao_code': airport.icao_code,
        'city': airport.city,
        'country': airport.country
    }), 200


# 5. Список маршрутов
@app.route('/api/v1/routes', methods=['GET'])
@jwt_required()
@cashier_required
def get_routes():
    routes = Route.query.all()
    return jsonify([{
        'id': r.id,
        'departure_airport': {
            'id': r.departure_airport.id,
            'name': r.departure_airport.name,
            'iata_code': r.departure_airport.iata_code
        },
        'arrival_airport': {
            'id': r.arrival_airport.id,
            'name': r.arrival_airport.name,
            'iata_code': r.arrival_airport.iata_code
        },
        'distance': r.distance,
        'flight_time': r.flight_time
    } for r in routes]), 200


# 6. Информация о маршруте
@app.route('/api/v1/routes/<int:route_id>', methods=['GET'])
@jwt_required()
@cashier_required
def get_route(route_id):
    route = Route.query.get_or_404(route_id)
    return jsonify({
        'id': route.id,
        'departure_airport': {
            'id': route.departure_airport.id,
            'name': route.departure_airport.name,
            'iata_code': route.departure_airport.iata_code
        },
        'arrival_airport': {
            'id': route.arrival_airport.id,
            'name': route.arrival_airport.name,
            'iata_code': route.arrival_airport.iata_code
        },
        'distance': route.distance,
        'flight_time': route.flight_time
    }), 200


# 7. Список рейсов с фильтрацией
@app.route('/api/v1/flights', methods=['GET'])
@jwt_required()
@cashier_required
def get_flights():
    # Параметры фильтрации
    route_id = request.args.get('route_id')
    date = request.args.get('date')
    status = request.args.get('status')

    query = Flight.query

    if route_id:
        query = query.filter_by(route_id=route_id)
    if date:
        query = query.filter(db.func.date(Flight.departure_time) == date)
    if status:
        query = query.filter_by(status=status)

    flights = query.all()

    return jsonify([{
        'id': f.id,
        'route_id': f.route_id,
        'departure_time': f.departure_time.isoformat(),
        'arrival_time': f.arrival_time.isoformat(),
        'aircraft_type': f.aircraft_type,
        'total_seats': f.total_seats,
        'available_seats': f.available_seats,
        'status': f.status,
        'base_price': f.base_price
    } for f in flights]), 200


# 8. Информация о рейсе
@app.route('/api/v1/flights/<int:flight_id>', methods=['GET'])
@jwt_required()
@cashier_required
def get_flight(flight_id):
    flight = Flight.query.get_or_404(flight_id)
    return jsonify({
        'id': flight.id,
        'route_id': flight.route_id,
        'departure_time': flight.departure_time.isoformat(),
        'arrival_time': flight.arrival_time.isoformat(),
        'aircraft_type': flight.aircraft_type,
        'total_seats': flight.total_seats,
        'available_seats': flight.available_seats,
        'status': flight.status,
        'base_price': flight.base_price
    }), 200


# 9. Доступные места на рейсе
@app.route('/api/v1/flights/<int:flight_id>/available', methods=['GET'])
@jwt_required()
@cashier_required
def get_available_seats(flight_id):
    flight = Flight.query.get_or_404(flight_id)
    economy = int(flight.available_seats * 0.8)
    business = int(flight.available_seats * 0.15)
    first = int(flight.available_seats * 0.05)
    if sum([economy, business, first]) != flight.available_seats:
        economy += flight.available_seats - sum([economy, business, first])

    return jsonify({
        'flight_id': flight.id,
        'available_seats': flight.available_seats,
        'seat_classes': {
            'economy': economy,
            'business': business,
            'first': first
        }
    }), 200


# 10. Создание пассажира
@app.route('/api/v1/passengers', methods=['POST'])
@jwt_required()
@cashier_required
def create_passenger():
    data = request.get_json()

    # Проверка существующего пассажира по паспорту
    existing = Passenger.query.filter_by(passport_number=data.get('passport_number')).first()
    if existing:
        return jsonify({
            'id': existing.id,
            'first_name': existing.first_name,
            'last_name': existing.last_name,
            'passport_number': existing.passport_number,
            'msg': 'Passenger already exists'
        }), 200

    passenger = Passenger(
        first_name=data['first_name'],
        last_name=data['last_name'],
        passport_number=data['passport_number'],
        phone=data.get('phone'),
        email=data.get('email')
    )

    db.session.add(passenger)
    db.session.commit()

    return jsonify({
        'id': passenger.id,
        'first_name': passenger.first_name,
        'last_name': passenger.last_name,
        'passport_number': passenger.passport_number,
        'phone': passenger.phone,
        'email': passenger.email
    }), 201


# 11. Информация о пассажире
@app.route('/api/v1/passengers/<int:passenger_id>', methods=['GET'])
@jwt_required()
@cashier_required
def get_passenger(passenger_id):
    passenger = Passenger.query.get_or_404(passenger_id)
    return jsonify({
        'id': passenger.id,
        'first_name': passenger.first_name,
        'last_name': passenger.last_name,
        'passport_number': passenger.passport_number,
        'phone': passenger.phone,
        'email': passenger.email
    }), 200


# 12. Обновление пассажира
@app.route('/api/v1/passengers/<int:passenger_id>', methods=['PUT'])
@jwt_required()
@cashier_required
def update_passenger(passenger_id):
    passenger = Passenger.query.get_or_404(passenger_id)
    data = request.get_json()

    if 'first_name' in data:
        passenger.first_name = data['first_name']
    if 'last_name' in data:
        passenger.last_name = data['last_name']
    if 'phone' in data:
        passenger.phone = data['phone']
    if 'email' in data:
        passenger.email = data['email']

    db.session.commit()

    return jsonify({
        'id': passenger.id,
        'first_name': passenger.first_name,
        'last_name': passenger.last_name,
        'passport_number': passenger.passport_number,
        'phone': passenger.phone,
        'email': passenger.email
    }), 200


# 13. Создание билета
@app.route('/api/v1/tickets', methods=['POST'])
@jwt_required()
@cashier_required
def create_ticket():
    data = request.get_json()
    claims = get_jwt()
    cashier_id = claims['cashier_id']

    # Проверка существования пассажира и рейса
    passenger = Passenger.query.get_or_404(data['passenger_id'])
    flight = Flight.query.get_or_404(data['flight_id'])

    # Проверка доступности мест
    if flight.available_seats <= 0:
        return jsonify({"msg": "No available seats on this flight"}), 400

    # Создание билета
    ticket = Ticket(
        passenger_id=passenger.id,
        flight_id=flight.id,
        seat_number=data.get('seat_number'),
        seat_class=data.get('seat_class', 'economy'),
        price=data['price'],
        issue_date=db.func.now()
    )

    # Обновление количества доступных мест
    flight.available_seats -= 1

    db.session.add(ticket)
    db.session.commit()

    return jsonify({
        'id': ticket.id,
        'passenger_id': ticket.passenger_id,
        'flight_id': ticket.flight_id,
        'seat_number': ticket.seat_number,
        'seat_class': ticket.seat_class,
        'price': ticket.price,
        'issue_date': ticket.issue_date.isoformat(),
        'status': ticket.status
    }), 201


# 14. Информация о билете
@app.route('/api/v1/tickets/<int:ticket_id>', methods=['GET'])
@jwt_required()
@cashier_required
def get_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    return jsonify({
        'id': ticket.id,
        'passenger_id': ticket.passenger_id,
        'flight_id': ticket.flight_id,
        'seat_number': ticket.seat_number,
        'seat_class': ticket.seat_class,
        'price': ticket.price,
        'issue_date': ticket.issue_date.isoformat(),
        'status': ticket.status
    }), 200


# 15. Аннулирование билета
@app.route('/api/v1/tickets/<int:ticket_id>', methods=['DELETE'])
@jwt_required()
@cashier_required
def cancel_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    flight = Flight.query.get(ticket.flight_id)

    # Возврат места
    if flight:
        flight.available_seats += 1

    # Аннулирование билета
    ticket.status = 'canceled'
    db.session.commit()

    return jsonify({"msg": "Ticket canceled successfully"}), 200


# 16. Информация о кассире
@app.route('/api/v1/cashiers/<int:cashier_id>', methods=['GET'])
@jwt_required()
def get_cashier(cashier_id):
    claims = get_jwt()
    if claims['cashier_id'] != cashier_id and claims['role'] != 'admin':
        return jsonify({"msg": "Access denied"}), 403

    cashier = Cashier.query.get_or_404(cashier_id)
    return jsonify({
        'id': cashier.id,
        'username': cashier.username,
        'full_name': cashier.full_name,
        'role': cashier.role
    }), 200


# 17. Информация о кассе
@app.route('/api/v1/kassas/<int:kassa_id>', methods=['GET'])
@jwt_required()
@cashier_required
def get_kassa(kassa_id):
    kassa = Kassa.query.get_or_404(kassa_id)
    return jsonify({
        'id': kassa.id,
        'name': kassa.name,
        'location': kassa.location,
        'is_active': kassa.is_active
    }), 200


# 18. Создание брони
@app.route('/api/v1/reservations', methods=['POST'])
@jwt_required()
@cashier_required
def create_reservation():
    data = request.get_json()
    claims = get_jwt()
    cashier_id = claims['cashier_id']

    passenger = Passenger.query.get_or_404(data['passenger_id'])
    flight = Flight.query.get_or_404(data['flight_id'])

    # Проверка доступности мест
    if flight.available_seats <= 0:
        return jsonify({"msg": "No available seats on this flight"}), 400

    # Создание брони
    reservation = Reservation(
        passenger_id=passenger.id,
        flight_id=flight.id,
        cashier_id=cashier_id,
        reservation_date=db.func.now(),
        status='active'
    )

    db.session.add(reservation)
    db.session.commit()

    return jsonify({
        'id': reservation.id,
        'passenger_id': reservation.passenger_id,
        'flight_id': reservation.flight_id,
        'cashier_id': reservation.cashier_id,
        'reservation_date': reservation.reservation_date.isoformat(),
        'status': reservation.status
    }), 201


# 19. Информация о брони
@app.route('/api/v1/reservations/<int:reservation_id>', methods=['GET'])
@jwt_required()
@cashier_required
def get_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    return jsonify({
        'id': reservation.id,
        'passenger_id': reservation.passenger_id,
        'flight_id': reservation.flight_id,
        'cashier_id': reservation.cashier_id,
        'reservation_date': reservation.reservation_date.isoformat(),
        'expiry_date': reservation.expiry_date.isoformat() if reservation.expiry_date else None,
        'status': reservation.status
    }), 200


# 20. Обновление брони
@app.route('/api/v1/reservations/<int:reservation_id>', methods=['PUT'])
@jwt_required()
@cashier_required
def update_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    data = request.get_json()

    if 'status' in data:
        reservation.status = data['status']
    if 'expiry_date' in data:
        reservation.expiry_date = data['expiry_date']

    db.session.commit()

    return jsonify({
        'id': reservation.id,
        'passenger_id': reservation.passenger_id,
        'flight_id': reservation.flight_id,
        'cashier_id': reservation.cashier_id,
        'reservation_date': reservation.reservation_date.isoformat(),
        'expiry_date': reservation.expiry_date.isoformat() if reservation.expiry_date else None,
        'status': reservation.status
    }), 200


# 21. Отмена брони
@app.route('/api/v1/reservations/<int:reservation_id>', methods=['DELETE'])
@jwt_required()
@cashier_required
def cancel_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)

    # Освобождение места, если бронь была активной
    if reservation.status == 'active':
        flight = Flight.query.get(reservation.flight_id)
        if flight:
            flight.available_seats += 1

    reservation.status = 'canceled'
    db.session.commit()

    return jsonify({"msg": "Reservation canceled successfully"}), 200


# 22. Создание договора
@app.route('/api/v1/contracts', methods=['POST'])
@jwt_required()
@cashier_required
def create_contract():
    data = request.get_json()
    claims = get_jwt()
    cashier_id = claims['cashier_id']

    reservation = Reservation.query.get_or_404(data['reservation_id'])

    # Создание договора
    contract = Contract(
        reservation_id=reservation.id,
        cashier_id=cashier_id,
        contract_number=data['contract_number'],
        contract_date=db.func.now(),
        total_amount=data['total_amount'],
        contract_type=data.get('contract_type')
    )

    db.session.add(contract)
    db.session.commit()

    return jsonify({
        'id': contract.id,
        'reservation_id': contract.reservation_id,
        'cashier_id': contract.cashier_id,
        'contract_number': contract.contract_number,
        'contract_date': contract.contract_date.isoformat(),
        'total_amount': contract.total_amount,
        'contract_type': contract.contract_type
    }), 201


# 23. Информация о договоре
@app.route('/api/v1/contracts/<int:contract_id>', methods=['GET'])
@jwt_required()
@cashier_required
def get_contract(contract_id):
    contract = Contract.query.get_or_404(contract_id)
    return jsonify({
        'id': contract.id,
        'reservation_id': contract.reservation_id,
        'cashier_id': contract.cashier_id,
        'contract_number': contract.contract_number,
        'contract_date': contract.contract_date.isoformat(),
        'total_amount': contract.total_amount,
        'contract_type': contract.contract_type
    }), 200


# 24. Создание платежа
@app.route('/api/v1/payments', methods=['POST'])
@jwt_required()
@cashier_required
def create_payment():
    data = request.get_json()

    contract = Contract.query.get_or_404(data['contract_id'])

    # Создание платежа
    payment = Payment(
        contract_id=contract.id,
        payment_date=db.func.now(),
        amount=data['amount'],
        payment_method=data.get('payment_method', 'cash'),
        status='completed'
    )

    db.session.add(payment)
    db.session.commit()

    return jsonify({
        'id': payment.id,
        'contract_id': payment.contract_id,
        'payment_date': payment.payment_date.isoformat(),
        'amount': payment.amount,
        'payment_method': payment.payment_method,
        'status': payment.status
    }), 201


# 25. Информация о платеже
@app.route('/api/v1/payments/<int:payment_id>', methods=['GET'])
@jwt_required()
@cashier_required
def get_payment(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    return jsonify({
        'id': payment.id,
        'contract_id': payment.contract_id,
        'payment_date': payment.payment_date.isoformat(),
        'amount': payment.amount,
        'payment_method': payment.payment_method,
        'status': payment.status
    }), 200


# 26. Отчет о рейсах
@app.route('/api/v1/reports/flights', methods=['GET'])
@jwt_required()
@cashier_required
def get_flights_report():
    # Параметры фильтрации
    date = request.args.get('date')
    route_id = request.args.get('route_id')
    status = request.args.get('status')

    query = db.session.query(
        Flight.id,
        Flight.route_id,
        Route.departure_airport_id,
        Route.arrival_airport_id,
        Flight.departure_time,
        Flight.arrival_time,
        Flight.status,
        Flight.available_seats,
        Flight.total_seats,
        db.func.count(Ticket.id).label('tickets_sold'),
        db.func.sum(Ticket.price).label('total_revenue')
    ).join(Route, Flight.route_id == Route.id
           ).outerjoin(Ticket, Ticket.flight_id == Flight.id
                       ).group_by(Flight.id)

    if date:
        query = query.filter(db.func.date(Flight.departure_time) == date)
    if route_id:
        query = query.filter(Flight.route_id == route_id)
    if status:
        query = query.filter(Flight.status == status)

    flights = query.all()

    # Агрегированные данные
    total_flights = len(flights)
    total_revenue = sum(f.total_revenue or 0 for f in flights)
    avg_load_factor = sum(
        (1 - (f.available_seats / f.total_seats)) for f in flights) / total_flights * 100 if total_flights > 0 else 0

    return jsonify({
        'total_flights': total_flights,
        'total_revenue': total_revenue,
        'average_load_factor': round(avg_load_factor, 2),
        'flights': [{
            'id': f.id,
            'route_id': f.route_id,
            'departure_airport_id': f.departure_airport_id,
            'arrival_airport_id': f.arrival_airport_id,
            'departure_time': f.departure_time.isoformat(),
            'arrival_time': f.arrival_time.isoformat(),
            'status': f.status,
            'available_seats': f.available_seats,
            'total_seats': f.total_seats,
            'tickets_sold': f.tickets_sold,
            'revenue': float(f.total_revenue) if f.total_revenue else 0,
            'load_factor': round((1 - (f.available_seats / f.total_seats)) * 100, 2) if f.total_seats > 0 else 0
        } for f in flights]
    }), 200


# 27. Отчет о билетах
@app.route('/api/v1/reports/tickets', methods=['GET'])
@jwt_required()
@cashier_required
def get_tickets_report():
    # Параметры фильтрации
    date = request.args.get('date')
    cashier_id = request.args.get('cashier_id')
    flight_id = request.args.get('flight_id')

    query = db.session.query(
        Ticket.id,
        Ticket.flight_id,
        Flight.route_id,
        Ticket.passenger_id,
        Passenger.first_name,
        Passenger.last_name,
        Ticket.seat_class,
        Ticket.price,
        Ticket.issue_date,
        Ticket.status,
        Cashier.full_name.label('cashier_name')
    ).join(Flight, Ticket.flight_id == Flight.id
           ).join(Passenger, Ticket.passenger_id == Passenger.id
                  ).join(Reservation, (Reservation.passenger_id == Passenger.id) & (Reservation.flight_id == Flight.id)
                         ).join(Cashier, Reservation.cashier_id == Cashier.id)

    if date:
        query = query.filter(db.func.date(Ticket.issue_date) == date)
    if cashier_id:
        query = query.filter(Reservation.cashier_id == cashier_id)
    if flight_id:
        query = query.filter(Ticket.flight_id == flight_id)

    tickets = query.all()

    # Агрегированные данные
    total_tickets = len(tickets)
    total_revenue = sum(t.price for t in tickets)
    avg_price = total_revenue / total_tickets if total_tickets > 0 else 0

    return jsonify({
        'total_tickets': total_tickets,
        'total_revenue': total_revenue,
        'average_price': round(avg_price, 2),
        'tickets': [{
            'id': t.id,
            'flight_id': t.flight_id,
            'route_id': t.route_id,
            'passenger_id': t.passenger_id,
            'passenger_name': f"{t.first_name} {t.last_name}",
            'seat_class': t.seat_class,
            'price': t.price,
            'issue_date': t.issue_date.isoformat(),
            'status': t.status,
            'cashier_name': t.cashier_name
        } for t in tickets]
    }), 200


if __name__ == '__main__':
    app.run(debug=True)