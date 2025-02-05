/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
    return knex.schema.createTable('video', function(table) {
        table.increments('id').primary();
        table.integer('user_id').unsigned().notNullable().references('id').inTable('user').onDelete('CASCADE');
        table.string('title').notNullable();
        table.text('description');
        table.string('url').notNullable();
        table.string('thumbnail');
        table.integer('views_count').defaultTo(0);
        table.integer('likes_count').defaultTo(0);
        table.integer('dislikes_count').defaultTo(0);
        table.binary('file').notNullable();
        table.timestamp('created_at').defaultTo(knex.fn.now());
        table.timestamp('updated_at').defaultTo(knex.fn.now());
    });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
    return knex.schema.dropTable('video');
};