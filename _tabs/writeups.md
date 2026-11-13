---
layout: page
title: Writeups
icon: fas fa-flag
order: 1
---

{% include lang.html %}

<p class="text-muted" style="margin-top: -0.5rem;">HackTheBox, TryHackMe and Vulnhub boxes.</p>

<div id="post-list" class="flex-grow-1 px-xl-1">
{% for post in site.posts %}
  {% if post.categories contains 'HackTheBox' or post.categories contains 'TryHackMe' or post.categories contains 'Vulnhub' %}
  {% include post-card.html %}
  {% endif %}
{% endfor %}
</div>
