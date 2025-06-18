  document.getElementById('sql-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('sql-username').value;
    const password = document.getElementById('sql-password').value;

    const res = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await res.json();
    document.getElementById('sql-output').innerText = data.result;
  });

  document.getElementById('xss-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const comment = document.getElementById('xss-input').value;

    const res = await fetch('/comment', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ comment })
    });

    const data = await res.text();
    const commentBox = document.getElementById('xss-comments');
    commentBox.innerHTML += `<div>${data}</div>`;
    document.getElementById('xss-input').value = '';
  });
