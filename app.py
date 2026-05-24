#!/usr/bin/env python3
"""
溧阳狄氏家谱查询系统 v3.0
- 多用户认证（登录/注册）
- 三级权限（管理员/编辑/访客）
- 基于30,033人完整数据库
"""

import sqlite3
import os
import hashlib
import secrets
from functools import wraps
from flask import Flask, render_template, jsonify, request, g, session, redirect, url_for, flash

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.secret_key = secrets.token_hex(32)  # 生成随机密钥

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'di_genealogy.db')

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

app.teardown_appcontext(close_db)

# ============================================================
# 初始化用户表
# ============================================================
def init_users():
    db = sqlite3.connect(DB_PATH)
    c = db.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT DEFAULT 'viewer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # 创建默认管理员
    try:
        pw = hashlib.sha256('admin123'.encode()).hexdigest()
        c.execute("INSERT OR IGNORE INTO users (username, password_hash, display_name, role) VALUES (?,?,?,?)",
                  ('admin', pw, '管理员', 'admin'))
    except: pass
    db.commit()
    db.close()

init_users()

# ============================================================
# 认证工具函数
# ============================================================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_current_user():
    if 'user_id' in session:
        db = get_db()
        return db.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page', next=request.path))
        return f(*args, **kwargs)
    return decorated

def role_required(min_role):
    """min_role: 'admin' > 'editor' > 'viewer'"""
    roles_order = {'admin': 3, 'editor': 2, 'viewer': 1}
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login_page'))
            user = get_current_user()
            if roles_order.get(user['role'], 0) < roles_order.get(min_role, 0):
                return jsonify({'error': '权限不足'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ============================================================
# 认证页面路由
# ============================================================
@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if user and user['password_hash'] == hash_password(password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['display_name'] = user['display_name']
        return jsonify({'ok': True, 'role': user['role'], 'name': user['display_name']})
    return jsonify({'ok': False, 'error': '用户名或密码错误'}), 401

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    display_name = data.get('display_name', username)
    
    if not username or len(username) < 2:
        return jsonify({'ok': False, 'error': '用户名至少2个字符'}), 400
    if not password or len(password) < 4:
        return jsonify({'ok': False, 'error': '密码至少4个字符'}), 400
    
    db = get_db()
    try:
        db.execute("INSERT INTO users (username, password_hash, display_name, role) VALUES (?,?,?,'viewer')",
                   (username, hash_password(password), display_name))
        db.commit()
        return jsonify({'ok': True, 'msg': '注册成功，请登录'})
    except sqlite3.IntegrityError:
        return jsonify({'ok': False, 'error': '用户名已存在'}), 409

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/me')
def api_me():
    user = get_current_user()
    if user:
        return jsonify({'logged_in': True, 'username': user['username'], 'role': user['role'], 'display_name': user['display_name']})
    return jsonify({'logged_in': False})



# ============================================================
# 前端页面路由（需登录）
# ============================================================
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/search')
@login_required
def search_page():
    return render_template('search.html')

@app.route('/person/<int:person_id>')
@login_required
def person_page(person_id):
    return render_template('person.html', person_id=person_id)

@app.route('/tree')
@login_required
def tree_page():
    return render_template('tree.html')

@app.route('/stats')
@login_required
def stats_page():
    return render_template('stats.html')

# ============================================================
# 管理员路由
# ============================================================
@app.route('/admin')
@role_required('admin')
def admin_page():
    return render_template('admin.html')

@app.route('/api/admin/users')
@role_required('admin')
def api_admin_users():
    db = get_db()
    users = db.execute("SELECT id, username, display_name, role, created_at FROM users ORDER BY id").fetchall()
    return jsonify([dict(u) for u in users])

@app.route('/api/admin/users/<int:uid>', methods=['PUT'])
@role_required('admin')
def api_update_user(uid):
    data = request.get_json()
    db = get_db()
    if 'role' in data:
        db.execute("UPDATE users SET role=? WHERE id=?", (data['role'], uid))
    if 'display_name' in data:
        db.execute("UPDATE users SET display_name=? WHERE id=?", (data['display_name'], uid))
    if 'password' in data and data['password']:
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(data['password']), uid))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/admin/users/<int:uid>', methods=['DELETE'])
@role_required('admin')
def api_delete_user(uid):
    db = get_db()
    db.execute("DELETE FROM users WHERE id=? AND username!='admin'", (uid,))
    db.commit()
    return jsonify({'ok': True})

# ============================================================
# API 数据接口
# ============================================================
@app.route('/api/stats')
@login_required
def api_stats():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM persons").fetchone()[0]
    family = db.execute("SELECT COUNT(*) FROM persons WHERE is_spouse=0").fetchone()[0]
    spouses = db.execute("SELECT COUNT(*) FROM persons WHERE is_spouse=1").fetchone()[0]
    relations = db.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
    gens = db.execute("SELECT shixi_num, COUNT(*) as cnt FROM persons WHERE shixi_num IS NOT NULL GROUP BY shixi_num ORDER BY shixi_num").fetchall()
    with_bio = db.execute("SELECT COUNT(*) FROM persons WHERE biography != '' AND biography IS NOT NULL").fetchone()[0]
    max_gen = db.execute("SELECT MAX(shixi_num) FROM persons").fetchone()[0] or 0
    return jsonify({
        'total': total, 'family': family, 'spouses': spouses, 'relations': relations,
        'with_bio': with_bio, 'max_gen': max_gen,
        'generations': [{'num': g['shixi_num'], 'count': g['cnt']} for g in gens]
    })

@app.route('/api/search')
@login_required
def api_search():
    q = request.args.get('q', '').strip()
    page = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 20)), 100)
    offset = (page - 1) * limit
    
    if not q:
        return jsonify({'results': [], 'total': 0, 'page': page})
    
    db = get_db()
    like_q = f'%{q}%'
    
    try:
        id_val = int(q)
        is_id = True
    except ValueError:
        is_id = False
    
    if is_id:
        results = db.execute("""
            SELECT id, original_id, full_name, shixi, shixi_num, zibei, gender, is_spouse,
                   birth_date, death_date, tag, alias
            FROM persons WHERE original_id = ? OR id = ?
            ORDER BY shixi_num NULLS LAST LIMIT ? OFFSET ?
        """, (id_val, id_val, limit, offset)).fetchall()
        total = db.execute("SELECT COUNT(*) FROM persons WHERE original_id = ? OR id = ?", (id_val, id_val)).fetchone()[0]
    else:
        results = db.execute("""
            SELECT id, original_id, full_name, shixi, shixi_num, zibei, gender, is_spouse,
                   birth_date, death_date, tag, alias
            FROM persons WHERE full_name LIKE ? OR alias LIKE ? OR zibei LIKE ?
            ORDER BY CASE WHEN full_name = ? THEN 0 WHEN full_name LIKE ? THEN 1 ELSE 2 END,
                     shixi_num NULLS LAST LIMIT ? OFFSET ?
        """, (like_q, like_q, like_q, q, like_q, limit, offset)).fetchall()
        total = db.execute("SELECT COUNT(*) FROM persons WHERE full_name LIKE ? OR alias LIKE ? OR zibei LIKE ?",
                          (like_q, like_q, like_q)).fetchone()[0]
    
    return jsonify({
        'results': [{'id': r['id'], 'original_id': r['original_id'], 'name': r['full_name'],
                     'shixi': r['shixi'] or '', 'shixi_num': r['shixi_num'],
                     'zibei': r['zibei'] or '', 'gender': r['gender'], 'is_spouse': r['is_spouse'],
                     'birth': r['birth_date'] or '', 'death': r['death_date'] or '',
                     'tag': r['tag'] or '', 'alias': r['alias'] or ''} for r in results],
        'total': total, 'page': page, 'pages': (total + limit - 1) // limit
    })

@app.route('/api/person/<int:person_id>')
@login_required
def api_person_detail(person_id):
    db = get_db()
    person = db.execute("SELECT * FROM persons WHERE id = ? OR original_id = ? LIMIT 1", 
                        (person_id, person_id)).fetchone()
    if not person:
        return jsonify({'error': '未找到该人物'}), 404
    
    p = dict(person)
    
    # 祖先链
    ancestors = []
    current_fid = p['father_original_id']
    while current_fid:
        anc = db.execute("SELECT id, original_id, full_name, shixi, shixi_num, gender, alias FROM persons WHERE original_id = ?",
                         (current_fid,)).fetchone()
        if anc:
            ancestors.append(dict(anc))
            current_fid = anc['father_original_id']
        else:
            break
    p['ancestors'] = list(reversed(ancestors))
    
    # 子女
    children = db.execute("""
        SELECT p2.id, p2.original_id, p2.full_name, p2.shixi, p2.shixi_num, p2.gender, p2.birth_date, p2.is_spouse, r.rel_type
        FROM relationships r JOIN persons p2 ON p2.original_id = r.child_id
        WHERE r.parent_id = ? ORDER BY p2.shixi_num, p2.rank
    """, (p['original_id'],)).fetchall()
    p['children'] = [dict(c) for c in children]
    
    # 配偶
    spouses = db.execute("SELECT id, original_id, full_name, gender, birth_date, death_date FROM persons WHERE spouse_of_original_id = ? AND is_spouse = 1",
                         (p['original_id'],)).fetchall()
    p['spouses'] = [dict(s) for s in spouses]
    
    # 如果是配偶
    if p['is_spouse']:
        partner = db.execute("SELECT id, original_id, full_name, shixi, shixi_num FROM persons WHERE original_id = ?",
                             (p['spouse_of_original_id'],)).fetchone()
        p['partner'] = dict(partner) if partner else None
    
    # 兄弟姊妹
    siblings = []
    if p['father_original_id']:
        sib = db.execute("SELECT p2.id, p2.original_id, p2.full_name, p2.shixi_num, p2.gender, p2.birth_date, p2.is_spouse FROM persons p2 WHERE p2.father_original_id = ? AND p2.original_id != ? ORDER BY p2.rank, p2.original_id",
                         (p['father_original_id'], p['original_id'])).fetchall()
        siblings = [dict(s) for s in sib]
    p['siblings'] = siblings
    
    return jsonify(p)

@app.route('/api/tree/<int:person_id>')
@login_required
def api_tree_data(person_id):
    db = get_db()
    person = db.execute("SELECT id, original_id, full_name, shixi, shixi_num, gender FROM persons WHERE id = ? OR original_id = ? LIMIT 1",
                        (person_id, person_id)).fetchone()
    if not person:
        return jsonify({'error': '未找到'}), 404
    def get_descendants(oid, depth=0, max_depth=4):
        if depth > max_depth: return []
        kids = db.execute("SELECT p2.id, p2.original_id, p2.full_name, p2.shixi_num, p2.gender FROM relationships r JOIN persons p2 ON p2.original_id = r.child_id WHERE r.parent_id = ? AND r.rel_type = 'father' ORDER BY p2.rank, p2.original_id",
                          (oid,)).fetchall()
        return [dict(k) | {'children': get_descendants(k['original_id'], depth+1, max_depth)} for k in kids]
    
    return jsonify(dict(person) | {'children': get_descendants(person['original_id'])})

@app.route('/api/browse')
@login_required
def api_browse():
    gen = request.args.get('gen', type=int)
    page = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = (page - 1) * limit
    db = get_db()
    if gen:
        total = db.execute("SELECT COUNT(*) FROM persons WHERE shixi_num = ? AND is_spouse = 0", (gen,)).fetchone()[0]
        results = db.execute("SELECT id, original_id, full_name, gender, rank, zibei, alias, tag, birth_date, death_date FROM persons WHERE shixi_num = ? AND is_spouse = 0 ORDER BY rank, original_id LIMIT ? OFFSET ?",
                            (gen, limit, offset)).fetchall()
    else:
        total = db.execute("SELECT COUNT(*) FROM persons WHERE is_spouse = 0").fetchone()[0]
        results = db.execute("SELECT id, original_id, full_name, shixi, shixi_num, gender, rank, zibei, alias, tag, birth_date, death_date FROM persons WHERE is_spouse = 0 ORDER BY shixi_num, rank, original_id LIMIT ? OFFSET ?",
                            (limit, offset)).fetchall()
    return jsonify({'results': [dict(r) for r in results], 'total': total, 'page': page, 'pages': (total + limit - 1) // limit})

@app.route('/api/gen_tree/<int:gen>')
@login_required
def api_gen_tree(gen):
    db = get_db()
    persons = db.execute("SELECT p.id, p.original_id, p.full_name, p.gender, p.rank, p.zibei, p.tag, p.father_original_id, p.alias, p.birth_date, p.death_date FROM persons p WHERE p.shixi_num = ? AND p.is_spouse = 0 ORDER BY p.rank, p.original_id",
                         (gen,)).fetchall()
    return jsonify([{'id': p['id'], 'original_id': p['original_id'], 'name': p['full_name'],
                     'gender': p['gender'], 'rank': p['rank'], 'zibei': p['zibei'] or '',
                     'tag': p['tag'] or '', 'father_id': p['father_original_id'],
                     'alias': p['alias'] or '', 'birth': p['birth_date'] or '', 'death': p['death_date'] or ''} for p in persons])

if __name__ == '__main__':
    print("=" * 50)
    print("溧阳狄氏家谱查询系统 v3.0 (多用户版)")
    print(f"数据库: {DB_PATH}")
    print("默认管理员: admin / admin123")
    print(f"启动地址: http://0.0.0.0:5000")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=False)