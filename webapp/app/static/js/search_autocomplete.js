// Shared query autocomplete and keyword controls for every search theme.
'use strict';

const TAG_SUGGEST_DEBOUNCE_MS = 120;
let tagSuggestAbortController = null;
let tagSuggestDebounceTimer = null;
let tagSuggestItems = [];
let tagSuggestSelectedIndex = -1;
let tagSuggestContext = null;
let tagSuggestRequestId = 0;

function getTagSuggestMenu() {
    return document.getElementById('query-tag-suggest');
}

function getQueryInput() {
    return document.querySelector('[data-query-autocomplete]') || document.getElementById('query');
}

function hideTagSuggestions() {
    tagSuggestRequestId += 1;
    if (tagSuggestAbortController) {
        tagSuggestAbortController.abort();
        tagSuggestAbortController = null;
    }
    if (tagSuggestDebounceTimer) {
        clearTimeout(tagSuggestDebounceTimer);
        tagSuggestDebounceTimer = null;
    }
    const menu = getTagSuggestMenu();
    if (menu) {
        menu.style.display = 'none';
        menu.innerHTML = '';
    }
    tagSuggestItems = [];
    tagSuggestSelectedIndex = -1;
    tagSuggestContext = null;
}

function getQueryTagContext() {
    const input = getQueryInput();
    if (!input) return null;
    const caret = input.selectionStart;
    if (caret === null || caret !== input.selectionEnd) return null;

    const query = input.value || '';
    let tokenStart = 0;
    let quote = null;
    let escaped = false;
    for (let index = 0; index < caret; index += 1) {
        const character = query[index];
        if (escaped) {
            escaped = false;
        } else if (character === '\\') {
            escaped = true;
        } else if (quote) {
            if (character === quote) quote = null;
        } else if (character === '"' || character === "'") {
            quote = character;
        } else if (/[\s()]/.test(character)) {
            tokenStart = index + 1;
        }
    }
    if (quote || escaped) return null;
    let tokenEnd = caret;
    while (tokenEnd < query.length && !/[\s()]/.test(query[tokenEnd])) {
        tokenEnd += 1;
    }
    const token = query.slice(tokenStart, tokenEnd);
    const prefix = query.slice(tokenStart, caret).toLowerCase();
    if (!prefix || /['"\\]/.test(token)) return null;
    const lowerToken = token.toLowerCase();
    let suggestType = 'keyword';
    if (prefix.startsWith('tag:')) {
        suggestType = 'tag';
    } else if (prefix.startsWith('http_headval:')) {
        if (lowerToken.slice('http_headval:'.length).includes(':')) return null;
        suggestType = 'header';
    } else if (!/^[a-z][a-z0-9_]*(?:\.[a-z]*)?$/i.test(token)) {
        return null;
    }
    return {input, query, caret, token, prefix, suggestType, tokenStart, tokenEnd};
}

function updateTagSuggestionSelection(nextIndex) {
    const menu = getTagSuggestMenu();
    if (!menu || !tagSuggestItems.length) {
        tagSuggestSelectedIndex = -1;
        return;
    }
    const buttons = [...menu.querySelectorAll('.tag-suggest-item')];
    if (!buttons.length) {
        tagSuggestSelectedIndex = -1;
        return;
    }

    const boundedIndex = Math.max(0, Math.min(nextIndex, buttons.length - 1));
    tagSuggestSelectedIndex = boundedIndex;
    buttons.forEach((button, index) => {
        button.classList.toggle('active', index === boundedIndex);
    });
    buttons[boundedIndex].scrollIntoView({ block: 'nearest' });
}

function applyTagSuggestion(index) {
    if (!tagSuggestContext || !tagSuggestItems[index]) {
        return;
    }

    const suggestion = tagSuggestItems[index];
    const input = tagSuggestContext.input;
    const currentValue = input.value || '';
    if (currentValue !== tagSuggestContext.query || input.selectionStart !== tagSuggestContext.caret || input.selectionEnd !== tagSuggestContext.caret) {
        hideTagSuggestions();
        return;
    }
    const before = currentValue.slice(0, tagSuggestContext.tokenStart);
    const after = currentValue.slice(tagSuggestContext.tokenEnd);
    const needsTrailingSpace = suggestion.kind === 'tag' && (after === '' || !/^\s/.test(after));
    const replacement = `${suggestion.value}${needsTrailingSpace ? ' ' : ''}`;
    input.value = `${before}${replacement}${after}`;
    const nextCaret = before.length + replacement.length;
    input.focus();
    input.setSelectionRange(nextCaret, nextCaret);

    if (suggestion.kind === 'namespace' || (suggestion.kind === 'keyword' && ['tag:', 'http_headval:'].includes(suggestion.value))) {
        scheduleTagSuggestionFetch();
        return;
    }
    hideTagSuggestions();
}

function renderTagSuggestions(suggestions, context) {
    const menu = getTagSuggestMenu();
    if (!menu) {
        return;
    }
    if (!suggestions.length) {
        hideTagSuggestions();
        return;
    }

    tagSuggestItems = suggestions;
    tagSuggestContext = context;
    menu.textContent = '';
    suggestions.forEach((suggestion, index) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'tag-suggest-item';
        button.dataset.index = String(index);

        const label = document.createElement('span');
        label.className = 'tag-suggest-label';
        label.textContent = suggestion.label || '';
        button.appendChild(label);

        const kind = document.createElement('span');
        kind.className = 'tag-suggest-kind';
        kind.textContent = suggestion.description || suggestion.kind || '';
        button.appendChild(kind);

        menu.appendChild(button);
    });
    menu.style.display = 'block';

    [...menu.querySelectorAll('.tag-suggest-item')].forEach((button) => {
        button.addEventListener('mousedown', (event) => {
            event.preventDefault();
        });
        button.addEventListener('click', () => {
            applyTagSuggestion(Number(button.dataset.index));
        });
    });
    updateTagSuggestionSelection(0);
}

async function fetchTagSuggestions(context) {
    if (tagSuggestAbortController) {
        tagSuggestAbortController.abort();
    }
    tagSuggestAbortController = new AbortController();
    const requestId = ++tagSuggestRequestId;

    try {
        const params = new URLSearchParams();
        params.set('term', context.token);
        const suggestPath = context.suggestType === 'header' ? 'header_suggest' : 'tag_suggest';
        const res = await fetch(`/kvsearchview/${suggestPath}?${params.toString()}`, {
            signal: tagSuggestAbortController.signal
        });
        if (!res.ok) throw new Error(`Suggestion request failed (${res.status})`);
        const data = await res.json();
        const latestContext = getQueryTagContext();
        if (requestId !== tagSuggestRequestId || !latestContext || latestContext.query !== context.query || latestContext.caret !== context.caret) {
            return;
        }
        renderTagSuggestions(data.suggestions || [], latestContext);
    } catch (error) {
        if (error?.name === 'AbortError' || requestId !== tagSuggestRequestId) {
            return;
        }
        hideTagSuggestions();
    }
}

function scheduleTagSuggestionFetch() {
    hideTagSuggestions();
    const context = getQueryTagContext();
    if (!context) return;
    if (context.suggestType === 'keyword') {
        const suggestions = buildSearchFieldSuggestions(context.prefix);
        renderTagSuggestions(suggestions, context);
        return;
    }
    tagSuggestDebounceTimer = setTimeout(() => {
        tagSuggestDebounceTimer = null;
        fetchTagSuggestions(context);
    }, TAG_SUGGEST_DEBOUNCE_MS);
}

function handleQueryKeydown(event) {
    if (event.isComposing) {
        return;
    }

    const menu = getTagSuggestMenu();
    const isOpen = menu && menu.style.display !== 'none' && tagSuggestItems.length > 0;
    if (!isOpen) {
        if (event.key === 'Enter') {
            if (typeof search === 'function') {
                event.preventDefault();
                search();
            }
        }
        return;
    }

    if (event.key === 'ArrowDown') {
        event.preventDefault();
        updateTagSuggestionSelection(tagSuggestSelectedIndex + 1);
    } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        updateTagSuggestionSelection(tagSuggestSelectedIndex - 1);
    } else if (event.key === 'Enter' || event.key === 'Tab') {
        event.preventDefault();
        applyTagSuggestion(tagSuggestSelectedIndex >= 0 ? tagSuggestSelectedIndex : 0);
    } else if (event.key === 'Escape') {
        event.preventDefault();
        hideTagSuggestions();
    }
}

function bindQueryTagHelper() {
    const input = getQueryInput();
    if (!input) {
        return;
    }

    input.addEventListener('input', () => {
        scheduleTagSuggestionFetch();
        if (typeof syncSinceDirectiveState === 'function') syncSinceDirectiveState();
    });
    input.addEventListener('click', scheduleTagSuggestionFetch);
    input.addEventListener('keydown', handleQueryKeydown);
    input.addEventListener('keyup', (event) => {
        if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
            scheduleTagSuggestionFetch();
        }
    });
    input.addEventListener('blur', () => {
        setTimeout(() => {
            const activeElement = document.activeElement;
            const menu = getTagSuggestMenu();
            if (menu && menu.contains(activeElement)) {
                return;
            }
            hideTagSuggestions();
        }, 120);
    });
}

const SEARCH_KEYWORDS = new Set(JSON.parse(
    document.getElementById('search-keywords')?.textContent || '[]'
));

function buildSearchFieldSuggestions(prefix) {
    const input = getQueryInput();
    const excluded = new Set((input?.dataset.queryAutocompleteDisallowed || '').split(',').filter(Boolean));
    const suggestions = [...SEARCH_KEYWORDS]
        .filter(keyword => keyword.startsWith(prefix) && !excluded.has(keyword))
        .map(keyword => {
            const value = keyword === 'nodata' ? keyword : `${keyword}:`;
            return {value, label: value, kind: 'keyword'};
        });
    const [field, modifier] = prefix.split('.');
    if (!SEARCH_KEYWORDS.has(field) || excluded.has(field) || ['tag', 'engine', 'nodata', 'since', 'http_headval'].includes(field)) {
        return suggestions;
    }
    const modifiers = modifier === undefined
        ? [['bg', 'starts with'], ['lk', 'contains']]
        : [['bg', 'starts with'], ['begin', 'starts with'], ['lk', 'contains'], ['like', 'contains']];
    for (const [suffix, description] of modifiers) {
        if (modifier !== undefined && !suffix.startsWith(modifier)) continue;
        const value = `${field}.${suffix}:`;
        suggestions.push({value, label: value, kind: 'modifier', description});
    }
    return suggestions;
}

function appendSearchKeyword(keyword) {
    if (!SEARCH_KEYWORDS.has(keyword)) {
        return;
    }
    appendSearchTerm(keyword === 'nodata' ? keyword : `${keyword}:`);
}

function appendSearchTerm(term) {
    const input = document.getElementById('query');
    if (!input) {
        return;
    }
    const prefix = input.value && !/\s$/.test(input.value) ? ' ' : '';
    input.value += `${prefix}${term}`;
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);
    input.dispatchEvent(new Event('input', {bubbles: true}));
}

function bindSearchKeywordHelpers() {
    bindSearchExampleHelp();
    bindSearchQueryExamples();
    document.querySelectorAll('[data-search-keyword]').forEach((keyword) => {
        const appendKeyword = () => appendSearchKeyword(keyword.dataset.searchKeyword);
        keyword.addEventListener('click', appendKeyword);
        keyword.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                appendKeyword();
            }
        });
    });
    document.querySelectorAll('[data-search-tag-term]').forEach((tag) => {
        tag.addEventListener('click', () => appendSearchTerm(tag.dataset.searchTagTerm));
    });
    document.querySelectorAll('[data-search-helper-toggle]').forEach((button) => {
        button.addEventListener('click', () => {
            const keywords = document.getElementById('search-keyword-table');
            const tags = document.getElementById('search-tag-table');
            const help = document.getElementById('scan-query-help');
            const showTags = help && !help.hidden
                ? help.dataset.previousTable !== 'search-tag-table' : tags.hidden;
            if (help) help.hidden = true;
            document.querySelectorAll('[data-search-examples-toggle]').forEach(control => {
                control.setAttribute('aria-expanded', 'false');
            });
            keywords.hidden = showTags;
            tags.hidden = !showTags;
            // The clicked control is now hidden: keep keyboard focus on its counterpart.
            (showTags ? tags : keywords).querySelector('[data-search-helper-toggle]').focus();
        });
    });
}

function bindSearchQueryExamples() {
    document.querySelectorAll('[data-query-example]').forEach(button => {
        button.addEventListener('click', () => {
            const input = document.getElementById('query');
            if (!input) return;
            input.value = button.dataset.queryExample;
            input.focus();
            input.setSelectionRange(input.value.length, input.value.length);
            input.dispatchEvent(new Event('input', {bubbles: true}));
        });
    });
}

function bindSearchExampleHelp() {
    const buttons = document.querySelectorAll('[data-search-examples-toggle]');
    buttons.forEach(button => {
        button.addEventListener('click', () => {
            const help = document.getElementById('scan-query-help');
            if (!help) return;
            const keywords = document.getElementById('search-keyword-table');
            const tags = document.getElementById('search-tag-table');
            if (help.hidden) {
                help.dataset.previousTable = tags.hidden ? 'search-keyword-table' : 'search-tag-table';
                keywords.hidden = true;
                tags.hidden = true;
                help.hidden = false;
                help.querySelector('[data-search-examples-toggle]').focus();
            } else {
                help.hidden = true;
                const previous = document.getElementById(help.dataset.previousTable);
                previous.hidden = false;
                previous.querySelector('[data-search-examples-toggle]').focus();
            }
            buttons.forEach(control => control.setAttribute('aria-expanded', String(!help.hidden)));
        });
    });
}
